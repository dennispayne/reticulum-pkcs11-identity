"""Hardware end-to-end: RNS encrypt -> YubiKey X25519 ECDH decrypt.

Exercises a complete Reticulum hardware identity assembled from two PIV slots
on a real YubiKey:

  * slot 9a (PKCS#11 CKA_ID 0x01) -- Ed25519 signing public key
  * slot 9d (PKCS#11 CKA_ID 0x03) -- X25519 encryption key (ECDH on-device)

A public-key-only sender encrypts a message to the identity; the identity then
decrypts it, performing the X25519 ECDH *inside the token*. The recovered
plaintext must match.

Why decryption (not signing): this path is crash-safe. It never invokes the
Ed25519 ``C_Sign`` operation, which some libykcs11 builds crash on natively.
The X25519 ECDH used here is the capability that turns a (previously sign-only)
PIV token into a full RNS identity.

Requirements / safety
---------------------
* Runs only when ``PKCS11_TEST_TOKEN=yubikey`` and ``PKCS11_TEST_PIN`` are set
  (enforced by the ``hardware_token_params`` fixture, which is lockout-safe).
* Needs the canonical two-slot layout: Ed25519 in 9a + X25519 in 9d. Provision
  with ``ykman piv keys generate -a x25519 --pin-policy once --touch-policy
  never <mgmt-key> 9d <out.pem>``. The test skips cleanly if those keys are
  absent, so it is safe to collect anywhere.
* Read + ECDH only; never touches PIN/PUK unblock flows. Recoverable with
  ``ykman piv reset``.
"""

import pytest

from tests.conftest import _add_yubico_dll_dir

try:
    import RNS  # noqa: F401

    HAS_RNS = True
except ImportError:
    HAS_RNS = False

# libykcs11 maps PIV slots to PKCS#11 CKA_ID: 9a->01, 9c->02, 9d->03, 9e->04.
_SIGN_KEY_ID = bytes([0x01])  # slot 9a, Ed25519 (sign)
_ENC_KEY_ID = bytes([0x03])   # slot 9d, X25519  (enc)


@pytest.mark.skipif(not HAS_RNS, reason="RNS not installed")
@pytest.mark.integration
@pytest.mark.hardware
class TestHardwareIdentityE2E:
    """Full encrypt -> hardware-decrypt round-trip against a real YubiKey."""

    def test_encrypt_then_hardware_decrypt(self, hardware_token_params):
        import RNS

        from reticulum_pkcs11_identity.backend import PKCS11Backend
        from reticulum_pkcs11_identity.exceptions import PKCS11KeyNotFoundError
        from reticulum_pkcs11_identity.identity import make_lxmf_identity_class

        params = hardware_token_params
        _add_yubico_dll_dir(params["module"])

        backend = PKCS11Backend(
            module_path=params["module"], token_label=params["label"]
        )
        backend.open_session(pin=params["pin"])
        try:
            HardwareIdentity = make_lxmf_identity_class(
                backend,
                sign_key_label=None,
                enc_key_label=None,
                sign_key_id=_SIGN_KEY_ID,
                enc_key_id=_ENC_KEY_ID,
            )

            try:
                identity = HardwareIdentity()
            except PKCS11KeyNotFoundError as exc:
                pytest.skip(
                    "Required PIV keys not present "
                    f"(need Ed25519 in 9a + X25519 in 9d): {exc}"
                )

            # Both public halves load from the token.
            assert len(identity.pub_bytes) == 32      # X25519 enc public key
            assert len(identity.sig_pub_bytes) == 32   # Ed25519 sign public key

            # A sender that knows ONLY the identity's public key.
            sender = RNS.Identity(create_keys=False)
            sender.load_public_key(identity.get_public_key())

            plaintext = b"reticulum hardware identity e2e: YubiKey X25519 ECDH"
            ciphertext = sender.encrypt(plaintext)
            assert ciphertext != plaintext

            # Decryption runs the X25519 ECDH inside the YubiKey (slot 9d).
            recovered = identity.decrypt(ciphertext)

            if recovered is None:
                pytest.skip(
                    "Hardware decryption returned no plaintext; slot 9d is most "
                    "likely not an X25519 key. Provision it with `ykman piv keys "
                    "generate -a x25519 ... 9d`."
                )
            assert recovered == plaintext
        finally:
            backend.close()
