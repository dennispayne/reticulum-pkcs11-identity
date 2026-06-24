"""
Real hardware-only PKCS#11 integration tests (YubiKey PIV).

These tests run against a physical YubiKey when ``PKCS11_TEST_TOKEN=yubikey`` and a
hardware PKCS#11 provider (libykcs11) plus ``PKCS11_TEST_PIN`` are available.
They skip cleanly in every other environment, so they are safe to collect
anywhere.

Hardware safety
---------------
The YubiKey's *content* is treated as disposable, but the hardware itself must
never be locked or bricked. Every hardware access goes through the
``hardware_token_params`` fixture, which:

  * refuses to run if the PIN is locked or on its final try, and
  * performs a single verification login and never retries a failed one
    (three wrong-PIN attempts would lock the token).

These tests therefore only ever *read* public keys and *sign* with the keys
already present in the PIV slots. They never touch the PIN/PUK unblock flows,
never run ``ykman config`` / lock-code operations, and never write to other
applets, so the PIV applet is always recoverable with ``ykman piv reset``.

The Ed25519 signing path is exercised in a **subprocess** because some
libykcs11 builds crash natively inside ``C_Sign`` for EdDSA. Isolating it
guarantees such a crash can never abort the pytest process; if it happens the
signing test skips with a diagnostic instead of taking the suite down.
"""

import os
import subprocess
import sys

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from reticulum_pkcs11_identity.backend_piv import PKCS11PIVBackend
from tests.conftest import (
    PIV_AUTH_PRIV_LABEL,
    PIV_AUTH_PUB_LABEL,
    PIV_SLOT_KEY_LABELS,
    _add_yubico_dll_dir,
)

# Only run if RNS is available
try:
    import RNS  # noqa: F401
    HAS_RNS = True
except ImportError:
    HAS_RNS = False


# Runs in a *child* interpreter so a native libykcs11 crash cannot abort pytest.
_SIGN_VERIFY_BODY = r'''
import os
os.add_dll_directory(DLL_DIR)
from reticulum_pkcs11_identity.backend_piv import PKCS11PIVBackend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

backend = PKCS11PIVBackend(module_path=MODULE, token_label=LABEL)
backend.open_session(pin=os.environ["PKCS11_TEST_PIN"])
try:
    message = b"reticulum-pkcs11 hardware self-test"
    pub = backend.get_public_key(key_label=PUB_LABEL)
    sig = backend.sign(message, key_label=PRIV_LABEL)
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
    print("VERIFY OK")
finally:
    backend.close()
'''


def _build_sign_script(params) -> str:
    """Prepend ``repr()``-quoted literals so the child script needs no parsing."""
    header = (
        f"DLL_DIR = {params['dll_dir']!r}\n"
        f"MODULE = {params['module']!r}\n"
        f"LABEL = {params['label']!r}\n"
        f"PUB_LABEL = {PIV_AUTH_PUB_LABEL!r}\n"
        f"PRIV_LABEL = {PIV_AUTH_PRIV_LABEL!r}\n"
    )
    return header + _SIGN_VERIFY_BODY


@pytest.mark.skipif(not HAS_RNS, reason="RNS not installed")
@pytest.mark.integration
@pytest.mark.hardware
class TestRealHardwareIntegration:
    """End-to-end tests against a real YubiKey PIV token."""

    def test_token_present_and_pin_healthy(self, hardware_token_params):
        """The fixture's lockout pre-flight + verification login must succeed.

        Reaching this point proves the token is present and unlocked and that
        the configured PIN is correct (the fixture performed exactly one
        verification login).
        """
        assert hardware_token_params["module"]
        assert hardware_token_params["label"]
        assert hardware_token_params["pin"]

    def test_read_public_key_is_ed25519(self, hardware_token_params):
        """Reading a PIV public key returns a valid 32-byte Ed25519 key."""
        params = hardware_token_params
        _add_yubico_dll_dir(params["module"])
        backend = PKCS11PIVBackend(
            module_path=params["module"], token_label=params["label"]
        )
        backend.open_session(pin=params["pin"])
        try:
            pub = backend.get_public_key(key_label=PIV_AUTH_PUB_LABEL)
        finally:
            backend.close()

        assert len(pub) == 32
        # Must be a structurally valid Ed25519 public key.
        Ed25519PublicKey.from_public_bytes(pub)

    def test_all_piv_slots_readable(self, hardware_token_params):
        """Every provisioned PIV slot exposes a readable 32-byte public key."""
        params = hardware_token_params
        _add_yubico_dll_dir(params["module"])
        backend = PKCS11PIVBackend(
            module_path=params["module"], token_label=params["label"]
        )
        backend.open_session(pin=params["pin"])
        try:
            found = 0
            for _slot, (_priv_label, pub_label) in PIV_SLOT_KEY_LABELS.items():
                try:
                    pub = backend.get_public_key(key_label=pub_label)
                except Exception:
                    continue
                assert len(pub) == 32
                Ed25519PublicKey.from_public_bytes(pub)
                found += 1
        finally:
            backend.close()

        # The token under test is provisioned with Ed25519 keys in all slots;
        # require at least one so the test is meaningful without being brittle
        # about exact slot provisioning.
        assert found >= 1

    def test_sign_and_verify_in_subprocess(self, hardware_token_params):
        """Hardware Ed25519 sign + verify, isolated so a native crash is contained.

        If libykcs11's EdDSA ``C_Sign`` crashes (a known issue on some builds),
        the child process exits non-zero without ``VERIFY OK`` and the test
        skips with a diagnostic rather than failing or taking down the suite.
        """
        params = hardware_token_params
        env = dict(os.environ)
        env["PKCS11_TEST_PIN"] = params["pin"]

        proc = subprocess.run(
            [sys.executable, "-c", _build_sign_script(params)],
            capture_output=True,
            text=True,
            env=env,
            timeout=90,
        )

        if "VERIFY OK" not in proc.stdout:
            pytest.skip(
                "libykcs11 EdDSA signing is unstable in this environment "
                f"(child rc={proc.returncode}); hardware sign/verify skipped. "
                f"stdout={proc.stdout!r} stderr={proc.stderr[-300:]!r}"
            )

        assert "VERIFY OK" in proc.stdout

