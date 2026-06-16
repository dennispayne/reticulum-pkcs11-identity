import unittest.mock as mock

import pytest

from reticulum_pkcs11_identity.exceptions import PKCS11KeyNotFoundError
from reticulum_pkcs11_identity.lxmf import (
    LXMFHardwareIdentityConfig,
    create_lxmf_hardware_identity,
    load_lxmf_hardware_identity_config,
)
from reticulum_pkcs11_identity.identity import (
    make_hardware_identity_class,
    make_lxmf_identity_class,
)


@pytest.mark.identity
def test_hardware_identity_sign_roundtrip(hardware_identity):
    msg = b"lxmf user identity message"
    sig = hardware_identity.sign(msg)
    assert hardware_identity.validate(sig, msg) is True


@pytest.mark.identity
def test_hardware_identity_encrypt_decrypt_roundtrip(hardware_identity):
    plaintext = b"hello from lxmf user"
    ciphertext = hardware_identity.encrypt(plaintext)
    assert hardware_identity.decrypt(ciphertext) == plaintext


@pytest.mark.identity
def test_make_hardware_identity_class_aliases_lxmf_factory(pkcs11_backend):
    cls_a = make_hardware_identity_class(
        backend=pkcs11_backend,
        sign_key_label="lxmf-sign",
        enc_key_label="lxmf-enc",
    )
    cls_b = make_lxmf_identity_class(
        backend=pkcs11_backend,
        sign_key_label="lxmf-sign",
        enc_key_label="lxmf-enc",
    )
    assert cls_a.__name__ == "LXMFIdentity"
    assert cls_b.__name__ == "LXMFIdentity"


@pytest.mark.lxmf
def test_lxmf_bootstrap_creates_missing_keys_and_closes_on_handle_close():
    fake_backend = mock.MagicMock()
    fake_backend.get_public_key_bytes.side_effect = [
        PKCS11KeyNotFoundError("missing sign"),
        PKCS11KeyNotFoundError("missing enc"),
    ]
    fake_identity_class = mock.MagicMock(return_value="identity-instance")
    fake_factory = mock.MagicMock(return_value=fake_identity_class)

    config = LXMFHardwareIdentityConfig(
        module_path="module.so",
        token_label="TokenA",
        pin="1234",
    )

    with mock.patch("reticulum_pkcs11_identity.lxmf.PKCS11Backend", return_value=fake_backend), mock.patch(
        "reticulum_pkcs11_identity.identity.make_lxmf_identity_class",
        fake_factory,
    ):
        handle = create_lxmf_hardware_identity(config)

    assert handle.identity == "identity-instance"
    fake_backend.open_session.assert_called_once()
    fake_backend.generate_ed25519_keypair.assert_called_once_with(
        label="lxmf-sign",
        key_id=None,
    )
    fake_backend.generate_x25519_keypair.assert_called_once_with(
        label="lxmf-enc",
        key_id=None,
    )
    handle.close()
    fake_backend.close.assert_called()


@pytest.mark.lxmf
def test_lxmf_bootstrap_resolves_pin_from_env(monkeypatch):
    fake_backend = mock.MagicMock()
    fake_backend.get_public_key_bytes.return_value = b"\xAA" * 32
    fake_identity_class = mock.MagicMock(return_value="identity-instance")
    fake_factory = mock.MagicMock(return_value=fake_identity_class)
    monkeypatch.setenv("LXMF_TEST_PIN", "2468")

    config = LXMFHardwareIdentityConfig(
        module_path="module.so",
        token_label="TokenA",
        pin_env="LXMF_TEST_PIN",
    )

    with mock.patch("reticulum_pkcs11_identity.lxmf.PKCS11Backend", return_value=fake_backend), mock.patch(
        "reticulum_pkcs11_identity.identity.make_lxmf_identity_class",
        fake_factory,
    ):
        handle = create_lxmf_hardware_identity(config)

    open_kwargs = fake_backend.open_session.call_args.kwargs
    assert open_kwargs["pin"] == "2468"
    handle.close()


@pytest.mark.lxmf
def test_lxmf_config_loader_reads_lxmf_section(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text(
        "[lxmf_pkcs11_identity]\n"
        "module = /usr/lib/softhsm/libsofthsm2.so\n"
        "token_label = LXMF-Token\n"
        "sign_key_label = custom-sign\n"
        "enc_key_label = custom-enc\n"
        "pin_env = CUSTOM_PIN_ENV\n"
    )

    loaded = load_lxmf_hardware_identity_config(str(cfg))

    assert loaded is not None
    assert loaded.module_path.endswith("libsofthsm2.so")
    assert loaded.token_label == "LXMF-Token"
    assert loaded.sign_key_label == "custom-sign"
    assert loaded.enc_key_label == "custom-enc"
    assert loaded.pin_env == "CUSTOM_PIN_ENV"


@pytest.mark.lxmf
def test_lxmf_config_loader_returns_none_for_missing_required_fields(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text(
        "[lxmf_pkcs11_identity]\n"
        "token_label = MissingModule\n"
    )

    loaded = load_lxmf_hardware_identity_config(str(cfg))

    assert loaded is None
