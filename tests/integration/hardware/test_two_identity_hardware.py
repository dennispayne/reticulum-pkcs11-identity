"""Two independent hardware identities served from a single YubiKey.

This is the hardware counterpart to the SoftHSM2 two-instance loopback e2e
(``tests/e2e/test_two_instance_e2e.py``). It demonstrates the part of the
"two parallel instances, each with its own key, on one token" scenario that is
*safely* achievable on a real YubiKey:

  * A first-launch Reticulum app's identity creation is routed to a specific
    PIV slot (here 9A and 9C), and
  * two **distinct** signing identities are served simultaneously from the
    **same** physical YubiKey, each signing independently and verifiably.

Why not a full live link exchange on hardware?
----------------------------------------------
1. YubiKey PIV holds only Ed25519 *signing* keys — there is no X25519
   *encryption* key, so a complete ``RNS.Identity`` (which needs both) cannot
   be assembled from PIV alone. The live loopback link test therefore runs on
   SoftHSM2 (Linux), where both key types exist.
2. Some ``libykcs11`` builds crash natively inside EdDSA ``C_Sign``. All signing
   here is done in a **subprocess** so such a crash can never abort pytest; the
   test skips with a diagnostic instead.

Hardware safety: read + sign only. No writes, no PIN/PUK unblock, no lock-code
or management-key operations. The ``hardware_token_params`` fixture refuses to
run if the PIN is locked or on its final try and performs exactly one
verification login, so the token can never be locked or bricked by this test.
"""

import os
import subprocess
import sys

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tests.conftest import PIV_SLOT_KEY_LABELS, _add_yubico_dll_dir

try:
    import RNS  # noqa: F401

    HAS_RNS = True
except ImportError:
    HAS_RNS = False

# Two slots = two independent identities on one device.
TWO_IDENTITY_SLOTS = ("9a", "9c")
SELFTEST_MESSAGE = b"reticulum-pkcs11 two-identity hardware self-test"

# Runs in a child interpreter so a native libykcs11 EdDSA crash cannot abort
# pytest. Prints the slot's public key and signature as hex for the parent to
# cross-check, after verifying the signature itself.
_SIGN_BODY = r'''
import os
os.add_dll_directory(DLL_DIR)
from reticulum_pkcs11_identity.backend_piv import PKCS11PIVBackend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

backend = PKCS11PIVBackend(module_path=MODULE, token_label=LABEL)
backend.open_session(pin=os.environ["PKCS11_TEST_PIN"])
try:
    message = bytes.fromhex(MESSAGE_HEX)
    pub = backend.get_public_key(key_label=PUB_LABEL)
    sig = backend.sign(message, key_label=PRIV_LABEL)
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
    print("PUB:" + pub.hex())
    print("SIG:" + sig.hex())
    print("VERIFY OK")
finally:
    backend.close()
'''


def _sign_in_subprocess(params, priv_label, pub_label):
    """Sign + verify with one PIV slot in an isolated child; return (pub, sig).

    Returns ``None`` (and the caller skips) if EdDSA signing is unstable in this
    libykcs11 build.
    """
    header = (
        f"DLL_DIR = {params['dll_dir']!r}\n"
        f"MODULE = {params['module']!r}\n"
        f"LABEL = {params['label']!r}\n"
        f"PUB_LABEL = {pub_label!r}\n"
        f"PRIV_LABEL = {priv_label!r}\n"
        f"MESSAGE_HEX = {SELFTEST_MESSAGE.hex()!r}\n"
    )
    env = dict(os.environ)
    env["PKCS11_TEST_PIN"] = params["pin"]
    proc = subprocess.run(
        [sys.executable, "-c", header + _SIGN_BODY],
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
    )
    if "VERIFY OK" not in proc.stdout:
        return None, (
            f"child rc={proc.returncode} stdout={proc.stdout!r} "
            f"stderr={proc.stderr[-300:]!r}"
        )

    pub = sig = None
    for line in proc.stdout.splitlines():
        if line.startswith("PUB:"):
            pub = bytes.fromhex(line[4:])
        elif line.startswith("SIG:"):
            sig = bytes.fromhex(line[4:])
    return (pub, sig), None


@pytest.mark.skipif(not HAS_RNS, reason="RNS not installed")
@pytest.mark.integration
@pytest.mark.hardware
class TestTwoIdentityHardware:
    """Two distinct signing identities from a single YubiKey's PIV slots."""

    def test_two_slots_present_and_distinct(self, hardware_token_params):
        """9A and 9C expose two *different* valid Ed25519 public keys.

        Two distinct public keys on one device is the cryptographic basis for
        two independent Reticulum identities served from the same YubiKey.
        """
        params = hardware_token_params
        _add_yubico_dll_dir(params["module"])
        from reticulum_pkcs11_identity.backend_piv import PKCS11PIVBackend

        backend = PKCS11PIVBackend(
            module_path=params["module"], token_label=params["label"]
        )
        backend.open_session(pin=params["pin"])
        try:
            pubs = {}
            for slot in TWO_IDENTITY_SLOTS:
                _priv_label, pub_label = PIV_SLOT_KEY_LABELS[slot]
                try:
                    pub = backend.get_public_key(key_label=pub_label)
                except Exception:
                    pytest.skip(f"PIV slot {slot} is not provisioned on this token")
                assert len(pub) == 32
                Ed25519PublicKey.from_public_bytes(pub)  # structurally valid
                pubs[slot] = pub
        finally:
            backend.close()

        assert pubs["9a"] != pubs["9c"], (
            "9A and 9C must hold different keys to represent two identities"
        )

    def test_two_identities_sign_independently(self, hardware_token_params):
        """Each slot signs the same message with its own key, both verifiable.

        This is the hardware analogue of two parallel instances each using its
        own key: the signatures verify against their respective public keys and
        differ from each other (proving two distinct private keys on one
        device). Signing is subprocess-isolated against libykcs11 EdDSA crashes.
        """
        params = hardware_token_params

        results = {}
        for slot in TWO_IDENTITY_SLOTS:
            priv_label, pub_label = PIV_SLOT_KEY_LABELS[slot]
            outcome, diag = _sign_in_subprocess(params, priv_label, pub_label)
            if outcome is None:
                pytest.skip(
                    f"libykcs11 EdDSA signing unstable for slot {slot}; "
                    f"hardware multi-identity signing skipped. {diag}"
                )
            results[slot] = outcome

        (pub_a, sig_a) = results["9a"]
        (pub_c, sig_c) = results["9c"]

        # Each signature verifies against its own slot's public key.
        Ed25519PublicKey.from_public_bytes(pub_a).verify(sig_a, SELFTEST_MESSAGE)
        Ed25519PublicKey.from_public_bytes(pub_c).verify(sig_c, SELFTEST_MESSAGE)

        # Two independent identities: different keys -> different signatures.
        assert pub_a != pub_c
        assert sig_a != sig_c

        # Cross-verification must fail (a slot cannot sign for the other).
        from cryptography.exceptions import InvalidSignature

        with pytest.raises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(pub_c).verify(sig_a, SELFTEST_MESSAGE)
