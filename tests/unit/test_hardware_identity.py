"""Tests for the generic hardware-identity binding loader.

These verify that the token/key binding is read from the ``[hardware_identity]``
config section, that sensible generic defaults are used, and -- importantly --
that a PIN is never read from the config file.
"""

import dataclasses
import os
import tempfile

from reticulum_pkcs11_identity.hardware_identity import (
    HardwareIdentityConfig,
    load_hardware_identity_binding,
)


def _write(tmpdir, body):
    path = os.path.join(tmpdir, "config")
    with open(path, "w") as fh:
        fh.write(body)
    return path


class TestLoadHardwareIdentityBinding:
    def test_reads_provider_and_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write(
                tmpdir,
                "[hardware_identity]\n"
                "provider = /usr/lib/libykcs11.so\n"
                "token_label = YubiKey PIV #12345\n",
            )
            cfg = load_hardware_identity_binding(path)
            assert cfg is not None
            assert cfg.module_path == "/usr/lib/libykcs11.so"
            assert cfg.token_label == "YubiKey PIV #12345"
            # Generic defaults -- not LXMF-specific.
            assert cfg.sign_key_label == "rns-sign"
            assert cfg.enc_key_label == "rns-enc"

    def test_custom_key_labels_and_ids(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write(
                tmpdir,
                "[hardware_identity]\n"
                "provider = libykcs11\n"
                "token_label = tok\n"
                "sign_key_label = my-sign\n"
                "enc_key_label = my-enc\n"
                "sign_key_id = 01\n"
                "enc_key_id = 03\n",
            )
            cfg = load_hardware_identity_binding(path)
            assert cfg.sign_key_label == "my-sign"
            assert cfg.enc_key_label == "my-enc"
            assert cfg.sign_key_id == b"01"
            assert cfg.enc_key_id == b"03"

    def test_missing_section_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write(tmpdir, "[something_else]\nfoo = bar\n")
            assert load_hardware_identity_binding(path) is None

    def test_missing_provider_or_token_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write(tmpdir, "[hardware_identity]\nenabled = true\n")
            assert load_hardware_identity_binding(path) is None

    def test_pin_in_config_is_never_loaded(self):
        # Even if a user puts a PIN in the config, the binding has no field for
        # it and never surfaces it.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write(
                tmpdir,
                "[hardware_identity]\n"
                "provider = libykcs11\n"
                "token_label = tok\n"
                "pin = 123456\n",
            )
            cfg = load_hardware_identity_binding(path)
            assert cfg is not None
            field_names = {f.name for f in dataclasses.fields(cfg)}
            assert "pin" not in field_names
            assert "pin_env" not in field_names
            assert not hasattr(cfg, "pin")
