import unittest.mock as mock

import pytest

from reticulum_pkcs11_identity.exceptions import PKCS11KeyNotFoundError
from reticulum_pkcs11_identity.hardware_identity import (
    HardwareIdentityConfig,
    create_hardware_identity,
    load_hardware_identity_binding,
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
def test_make_lxmf_identity_class_is_deprecated_alias(pkcs11_backend):
    # make_lxmf_identity_class is kept only as a backward-compatible alias for
    # the generic make_hardware_identity_class; both build the same class.
    cls_a = make_hardware_identity_class(
        backend=pkcs11_backend,
        sign_key_label="rns-sign",
        enc_key_label="rns-enc",
    )
    cls_b = make_lxmf_identity_class(
        backend=pkcs11_backend,
        sign_key_label="rns-sign",
        enc_key_label="rns-enc",
    )
    assert cls_a.__name__ == "HardwareIdentity"
    assert cls_b.__name__ == "HardwareIdentity"


@pytest.mark.identity
def test_bootstrap_creates_missing_keys_and_closes_on_handle_close():
    fake_backend = mock.MagicMock()
    fake_backend.get_public_key_bytes.side_effect = [
        PKCS11KeyNotFoundError("missing sign"),
        PKCS11KeyNotFoundError("missing enc"),
    ]
    fake_identity_class = mock.MagicMock(return_value="identity-instance")
    fake_factory = mock.MagicMock(return_value=fake_identity_class)

    config = HardwareIdentityConfig(
        module_path="module.so",
        token_label="TokenA",
    )

    with mock.patch("reticulum_pkcs11_identity.hardware_identity.PKCS11Backend", return_value=fake_backend), mock.patch(
        "reticulum_pkcs11_identity.identity.make_hardware_identity_class",
        fake_factory,
    ):
        handle = create_hardware_identity(config)

    assert handle.identity == "identity-instance"
    fake_backend.open_session.assert_called_once()
    fake_backend.generate_ed25519_keypair.assert_called_once_with(
        label="rns-sign",
        key_id=None,
    )
    fake_backend.generate_x25519_keypair.assert_called_once_with(
        label="rns-enc",
        key_id=None,
    )
    handle.close()
    fake_backend.close.assert_called()


@pytest.mark.identity
def test_bootstrap_passes_explicit_pin_to_backend():
    # The PIN is supplied programmatically by the caller, never read from config.
    fake_backend = mock.MagicMock()
    fake_backend.get_public_key_bytes.return_value = b"\xAA" * 32
    fake_identity_class = mock.MagicMock(return_value="identity-instance")
    fake_factory = mock.MagicMock(return_value=fake_identity_class)

    config = HardwareIdentityConfig(
        module_path="module.so",
        token_label="TokenA",
    )

    with mock.patch("reticulum_pkcs11_identity.hardware_identity.PKCS11Backend", return_value=fake_backend), mock.patch(
        "reticulum_pkcs11_identity.identity.make_hardware_identity_class",
        fake_factory,
    ):
        handle = create_hardware_identity(config, pin="2468")

    open_kwargs = fake_backend.open_session.call_args.kwargs
    assert open_kwargs["pin"] == "2468"
    handle.close()


@pytest.mark.identity
def test_binding_loader_reads_hardware_identity_section(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text(
        "[hardware_identity]\n"
        "provider = /usr/lib/softhsm/libsofthsm2.so\n"
        "token_label = RNS-Token\n"
        "sign_key_label = custom-sign\n"
        "enc_key_label = custom-enc\n"
    )

    loaded = load_hardware_identity_binding(str(cfg))

    assert loaded is not None
    assert loaded.module_path.endswith("libsofthsm2.so")
    assert loaded.token_label == "RNS-Token"
    assert loaded.sign_key_label == "custom-sign"
    assert loaded.enc_key_label == "custom-enc"


@pytest.mark.identity
def test_binding_loader_returns_none_for_missing_required_fields(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text(
        "[hardware_identity]\n"
        "token_label = MissingProvider\n"
    )

    loaded = load_hardware_identity_binding(str(cfg))

    assert loaded is None
