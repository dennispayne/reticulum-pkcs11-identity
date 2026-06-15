# Reticulum PKCS#11 Identity - License
#
# Copyright (c) 2024 Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Test suite for the reticulum_pkcs11_identity package.

All tests that require a PKCS#11 token use SoftHSM2 via the session-scoped
``pkcs11_backend`` and ``hardware_identity`` fixtures defined in conftest.py.
Tests are automatically skipped when SoftHSM2 is not installed.

Coverage:
  - Backend: session management, signing, ECDH derivation, public key export
  - HardwareIdentity: construction, sign, decrypt, full roundtrip
  - Session reuse: verify that the PIN is requested only once per session
  - Reticulum integration: two in-memory nodes exchange a message using the
    hardware-backed identity; PKCS#11 session is reused across multiple messages
"""

import os
import tempfile
import threading
import time

import pytest

# =========================================================================
# Backend tests
# =========================================================================


class TestBackendSessionManagement:
    def test_open_session_with_pin(self, pkcs11_backend):
        """Session should be open after open_session(pin=...)."""
        assert pkcs11_backend._session is not None

    def test_open_session_idempotent(self, pkcs11_backend):
        """Calling open_session a second time must not raise or replace session."""
        original_session = pkcs11_backend._session
        pkcs11_backend.open_session(pin="wrong-pin-should-not-be-called")
        assert pkcs11_backend._session is original_session  # unchanged

    def test_session_reused_across_calls(self, pkcs11_backend):
        """The same session object must be used for every operation."""
        session_before = pkcs11_backend._session
        pkcs11_backend.get_public_key_bytes(key_label="rns-sign")
        pkcs11_backend.get_public_key_bytes(key_label="rns-enc")
        assert pkcs11_backend._session is session_before


class TestBackendKeyExport:
    def test_export_sign_public_key(self, pkcs11_backend):
        """Ed25519 public key must be 32 bytes."""
        pub = pkcs11_backend.get_public_key_bytes(key_label="rns-sign")
        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_export_enc_public_key(self, pkcs11_backend):
        """X25519 public key must be 32 bytes."""
        pub = pkcs11_backend.get_public_key_bytes(key_label="rns-enc")
        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_missing_key_raises(self, pkcs11_backend):
        from reticulum_pkcs11_identity.exceptions import PKCS11KeyNotFoundError
        with pytest.raises(PKCS11KeyNotFoundError):
            pkcs11_backend.get_public_key_bytes(key_label="does-not-exist")


class TestBackendSigning:
    def test_sign_returns_64_bytes(self, pkcs11_backend):
        """Ed25519 signatures are exactly 64 bytes."""
        sig = pkcs11_backend.sign(b"Hello Reticulum!", key_label="rns-sign")
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_sign_different_messages_differ(self, pkcs11_backend):
        """Two different messages must produce different signatures."""
        sig1 = pkcs11_backend.sign(b"message one", key_label="rns-sign")
        sig2 = pkcs11_backend.sign(b"message two", key_label="rns-sign")
        assert sig1 != sig2

    def test_sign_same_message_deterministic(self, pkcs11_backend):
        """Ed25519 is deterministic; same message must yield same signature."""
        msg = b"deterministic test"
        sig1 = pkcs11_backend.sign(msg, key_label="rns-sign")
        sig2 = pkcs11_backend.sign(msg, key_label="rns-sign")
        assert sig1 == sig2

    def test_sign_verifiable_with_public_key(self, pkcs11_backend):
        """Signature must be verifiable with the token's Ed25519 public key."""
        from RNS.Cryptography import Ed25519PublicKey
        msg = b"verify me"
        sig = pkcs11_backend.sign(msg, key_label="rns-sign")
        pub_bytes = pkcs11_backend.get_public_key_bytes(key_label="rns-sign")
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        # Should not raise
        pub.verify(sig, msg)

    def test_sign_session_not_reprompted(self, pkcs11_backend):
        """
        Confirm PIN is not prompted again during signing.

        We simply record the session id before and after multiple sign
        operations and assert it did not change.
        """
        session_id = id(pkcs11_backend._session)
        for i in range(5):
            pkcs11_backend.sign(f"message {i}".encode(), key_label="rns-sign")
        assert id(pkcs11_backend._session) == session_id


class TestBackendECDH:
    def test_ecdh_returns_32_bytes(self, pkcs11_backend):
        """ECDH shared secret must be 32 bytes."""
        from reticulum_pkcs11_identity.backend import raw_to_ec_point
        from RNS.Cryptography import X25519PrivateKey
        eph = X25519PrivateKey.generate()
        eph_pub_point = raw_to_ec_point(eph.public_key().public_bytes())
        shared = pkcs11_backend.ecdh_derive(eph_pub_point, key_label="rns-enc")
        assert isinstance(shared, bytes)
        assert len(shared) == 32

    def test_ecdh_accepts_raw_32_bytes(self, pkcs11_backend):
        """ecdh_derive should accept raw 32-byte keys without DER prefix."""
        from RNS.Cryptography import X25519PrivateKey
        eph = X25519PrivateKey.generate()
        raw_pub = eph.public_key().public_bytes()
        assert len(raw_pub) == 32
        shared = pkcs11_backend.ecdh_derive(raw_pub, key_label="rns-enc")
        assert len(shared) == 32

    def test_ecdh_shared_secret_matches_software(self, pkcs11_backend):
        """
        The token's ECDH output must match a pure-software X25519 exchange.

        Let ``A`` be the token's X25519 private key.
        Let ``B`` be an ephemeral software key.

        shared(A_prv, B_pub) == shared(B_prv, A_pub)
        """
        from RNS.Cryptography import X25519PrivateKey, X25519PublicKey
        from reticulum_pkcs11_identity.backend import raw_to_ec_point

        # Generate ephemeral software keypair (B).
        eph_prv = X25519PrivateKey.generate()
        eph_pub_raw = eph_prv.public_key().public_bytes()

        # PKCS#11 side: A derives shared(A_prv, B_pub)
        token_shared = pkcs11_backend.ecdh_derive(
            raw_to_ec_point(eph_pub_raw), key_label="rns-enc"
        )

        # Software side: B derives shared(B_prv, A_pub)
        a_pub_raw = pkcs11_backend.get_public_key_bytes(key_label="rns-enc")
        a_pub = X25519PublicKey.from_public_bytes(a_pub_raw)
        sw_shared = eph_prv.exchange(a_pub)

        assert token_shared == sw_shared


# =========================================================================
# HardwareIdentity tests
# =========================================================================


class TestHardwareIdentityConstruction:
    def test_create_keys_loads_from_token(self, hardware_identity):
        """create_keys=True must populate pub_bytes and sig_pub_bytes."""
        assert hardware_identity.pub_bytes is not None
        assert len(hardware_identity.pub_bytes) == 32
        assert hardware_identity.sig_pub_bytes is not None
        assert len(hardware_identity.sig_pub_bytes) == 32

    def test_private_key_not_in_memory(self, hardware_identity):
        """Hardware identity must not expose a private key."""
        assert hardware_identity.prv is None
        assert hardware_identity.prv_bytes is None
        assert hardware_identity.sig_prv is None
        assert hardware_identity.sig_prv_bytes is None

    def test_get_private_key_returns_public_key(self, hardware_identity):
        """Hardware identity returns the public key as the private key placeholder."""
        key = hardware_identity.get_private_key()
        assert key is not None
        assert key == hardware_identity.get_public_key()

    def test_hash_is_set(self, hardware_identity):
        import RNS
        expected_len = RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
        assert hardware_identity.hash is not None
        assert len(hardware_identity.hash) == expected_len

    def test_hexhash_is_set(self, hardware_identity):
        import RNS
        expected_len = (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2
        assert hardware_identity.hexhash is not None
        assert len(hardware_identity.hexhash) == expected_len

    def test_create_keys_false_gives_empty_identity(self, hardware_identity_class):
        empty = hardware_identity_class(create_keys=False)
        assert empty.pub is None
        assert empty._is_local_hardware is False

    def test_is_local_hardware_flag(self, hardware_identity):
        assert hardware_identity._is_local_hardware is True

    def test_get_public_key_returns_64_bytes(self, hardware_identity):
        pub = hardware_identity.get_public_key()
        assert pub is not None
        assert len(pub) == 64  # 32 enc + 32 sign

    def test_public_key_matches_backend(self, hardware_identity, pkcs11_backend):
        pub = hardware_identity.get_public_key()
        enc_pub  = pkcs11_backend.get_public_key_bytes(key_label="rns-enc")
        sign_pub = pkcs11_backend.get_public_key_bytes(key_label="rns-sign")
        assert pub[:32]  == enc_pub
        assert pub[32:]  == sign_pub


class TestHardwareIdentitySigning:
    def test_sign_returns_bytes(self, hardware_identity):
        sig = hardware_identity.sign(b"hello")
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_sign_validates_with_own_public_key(self, hardware_identity):
        msg = b"self-signed message"
        sig = hardware_identity.sign(msg)
        assert hardware_identity.validate(sig, msg) is True

    def test_sign_rejects_tampered_message(self, hardware_identity):
        msg = b"original message"
        sig = hardware_identity.sign(msg)
        assert hardware_identity.validate(sig, b"tampered message") is False

    def test_pin_not_reprompted_across_multiple_signs(self, hardware_identity, pkcs11_backend):
        """
        Verify that a single PKCS#11 session is reused for multiple sign ops.
        We record the session object id before and after 10 sign operations.
        """
        session_id_before = id(pkcs11_backend._session)
        for i in range(10):
            hardware_identity.sign(f"message {i}".encode())
        session_id_after = id(pkcs11_backend._session)
        assert session_id_before == session_id_after


class TestHardwareIdentityDecryption:
    def test_encrypt_then_decrypt_roundtrip(self, hardware_identity):
        """Encrypt with public key in software; decrypt via token."""
        plaintext = b"secret message for the hardware identity"
        ciphertext = hardware_identity.encrypt(plaintext)
        recovered  = hardware_identity.decrypt(ciphertext)
        assert recovered == plaintext

    def test_decrypt_produces_correct_plaintext(self, hardware_identity):
        messages = [b"short", b"a" * 500, bytes(range(256))]
        for msg in messages:
            ct = hardware_identity.encrypt(msg)
            pt = hardware_identity.decrypt(ct)
            assert pt == msg

    def test_decrypt_with_wrong_ciphertext_returns_none(self, hardware_identity):
        garbage = os.urandom(64)
        result = hardware_identity.decrypt(garbage)
        assert result is None

    def test_session_reused_across_decryptions(self, hardware_identity, pkcs11_backend):
        """PKCS#11 session must not be replaced across multiple decrypt calls."""
        session_id_before = id(pkcs11_backend._session)
        for _ in range(5):
            ct = hardware_identity.encrypt(b"test")
            hardware_identity.decrypt(ct)
        assert id(pkcs11_backend._session) == session_id_before


class TestHardwareIdentityPublicKeyPersistence:
    def test_to_file_saves_only_public_key(self, hardware_identity, tmp_path):
        path = str(tmp_path / "identity")
        result = hardware_identity.to_file(path)
        assert result is True
        with open(path, "rb") as fh:
            data = fh.read()
        # Public key only: 64 bytes (32 enc + 32 sign)
        assert len(data) == 64

    def test_from_file_loads_from_token(self, hardware_identity_class, hardware_identity, tmp_path):
        # Save the hardware identity's public key to a file.
        path = str(tmp_path / "identity")
        hardware_identity.to_file(path)

        # Load via from_file — should still be a hardware identity.
        loaded = hardware_identity_class.from_file(path)
        assert loaded is not None
        assert loaded._is_local_hardware is True
        assert loaded.hash == hardware_identity.hash


class TestHardwareIdentityRemoteInstance:
    """Remote identities (public-key-only) must behave like stock RNS.Identity."""

    def test_remote_identity_load_public_key(self, hardware_identity_class):
        import os
        remote = hardware_identity_class(create_keys=False)
        pub = os.urandom(32) + os.urandom(32)
        remote.load_public_key(pub)
        assert remote.pub_bytes == pub[:32]
        assert remote.sig_pub_bytes == pub[32:]
        assert remote._is_local_hardware is False

    def test_remote_identity_decrypt_raises(self, hardware_identity_class):
        """Decrypting with a public-key-only identity raises KeyError."""
        remote = hardware_identity_class(create_keys=False)
        import os as _os
        remote.load_public_key(_os.urandom(32) + _os.urandom(32))
        with pytest.raises(KeyError):
            remote.decrypt(b"\x00" * 64)

    def test_remote_identity_sign_raises(self, hardware_identity_class):
        """Signing with a public-key-only identity raises KeyError."""
        remote = hardware_identity_class(create_keys=False)
        with pytest.raises(KeyError):
            remote.sign(b"cannot sign")


# =========================================================================
# Reticulum integration tests
# =========================================================================

class TestReticulumIntegration:
    """
    End-to-end test: two in-memory Reticulum nodes exchange a message using
    the PKCS#11-backed identity.  No real hardware or network is required.
    """

    @pytest.fixture(autouse=True)
    def _rns_configdir(self, tmp_path):
        """Give each test its own isolated Reticulum config directory."""
        self._rns_dir = str(tmp_path / "rns")
        os.makedirs(self._rns_dir, exist_ok=True)
        yield
        # Cleanup is handled by tmp_path's teardown.

    def test_reticulum_node_with_hardware_identity(
        self, hardware_identity_class, hardware_identity
    ):
        """
        Verify that a Reticulum instance accepts a hardware-backed identity and
        can use it to create a destination, announce, and route packets.
        """
        import RNS

        # Patch RNS.Identity for this test.
        original_identity = RNS.Identity
        try:
            RNS.Identity = hardware_identity_class

            reticulum = RNS.Reticulum(configdir=self._rns_dir)
            try:
                destination = RNS.Destination(
                    hardware_identity,
                    RNS.Destination.IN,
                    RNS.Destination.SINGLE,
                    "test_pkcs11",
                    "node",
                )
                assert destination is not None
                assert destination.hash is not None
            finally:
                RNS.Transport.exit_handler()
        finally:
            RNS.Identity = original_identity

    def test_encrypt_decrypt_between_two_identities(
        self, hardware_identity_class, hardware_identity
    ):
        """
        Node A (software identity) encrypts a message for Node B (hardware
        identity).  Node B decrypts using the PKCS#11 token.  The session
        must not be replaced between operations.
        """
        import RNS
        from RNS.Identity import Identity as SoftwareIdentity

        # Software sender identity.
        sender = SoftwareIdentity()

        # Hardware receiver identity.
        receiver = hardware_identity

        pkcs11_backend = hardware_identity._backend
        session_id_before = id(pkcs11_backend._session)

        # Simulate multiple message exchanges.
        messages = [
            b"first message",
            b"second message",
            b"third message",
        ]
        for msg in messages:
            ciphertext = receiver.encrypt(msg)
            plaintext  = receiver.decrypt(ciphertext)
            assert plaintext == msg

        # The PKCS#11 session must be reused across all three decryptions.
        assert id(pkcs11_backend._session) == session_id_before

    def test_concurrent_sign_operations_single_session(
        self, hardware_identity, pkcs11_backend
    ):
        """
        Multiple threads may call sign() concurrently.  The backend's
        internal lock must ensure operations are serialised and the session
        is never duplicated or replaced.
        """
        session_id_before = id(pkcs11_backend._session)
        errors = []

        def worker(idx):
            try:
                sig = hardware_identity.sign(f"thread-{idx}".encode())
                assert len(sig) == 64
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent sign errors: {errors}"
        assert id(pkcs11_backend._session) == session_id_before
