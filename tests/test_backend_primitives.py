"""
Tests for PKCS11Backend cryptographic primitives.

These tests exercise sign, ecdh_derive, get_public_key_bytes, and key generation
operations using a real SoftHSM2 token. Tests are skipped gracefully if SoftHSM2
is not available.
"""

import pytest

from reticulum_pkcs11_identity.backend import PKCS11Backend
from reticulum_pkcs11_identity.exceptions import (
    PKCS11BackendError,
    PKCS11KeyNotFoundError,
)


@pytest.mark.backend
@pytest.mark.primitives
class TestBackendPrimitives:
    """Test cryptographic primitives on a real PKCS#11 token."""

    def test_sign_produces_valid_signature(self, pkcs11_backend):
        """Sign operation produces a 64-byte Ed25519 signature."""
        message = b"Test message for signing"
        signature = pkcs11_backend.sign(message, key_label="lxmf-sign")

        assert isinstance(signature, bytes)
        assert len(signature) == 64

    def test_sign_different_messages_produce_different_signatures(self, pkcs11_backend):
        """Different messages produce different signatures."""
        msg1 = b"Message 1"
        msg2 = b"Message 2"

        sig1 = pkcs11_backend.sign(msg1, key_label="lxmf-sign")
        sig2 = pkcs11_backend.sign(msg2, key_label="lxmf-sign")

        assert sig1 != sig2

    def test_sign_same_message_produces_same_signature(self, pkcs11_backend):
        """Same message produces same signature (deterministic)."""
        message = b"Deterministic test"

        sig1 = pkcs11_backend.sign(message, key_label="lxmf-sign")
        sig2 = pkcs11_backend.sign(message, key_label="lxmf-sign")

        assert sig1 == sig2

    def test_get_public_key_bytes_returns_32_bytes(self, pkcs11_backend):
        """get_public_key_bytes returns a 32-byte raw key."""
        pub_key = pkcs11_backend.get_public_key_bytes(key_label="lxmf-sign")

        assert isinstance(pub_key, bytes)
        assert len(pub_key) == 32

    def test_get_public_key_bytes_enc_key_returns_32_bytes(self, pkcs11_backend):
        """get_public_key_bytes for encryption key also returns 32 bytes."""
        pub_key = pkcs11_backend.get_public_key_bytes(key_label="lxmf-enc")

        assert isinstance(pub_key, bytes)
        assert len(pub_key) == 32

    def test_ecdh_derive_with_peer_point_returns_32_bytes(self, pkcs11_backend):
        """ECDH derivation with peer's public point returns 32-byte shared secret."""
        # Generate a peer's public key point
        peer_pub = pkcs11_backend.get_public_key_bytes(key_label="lxmf-enc")
        assert len(peer_pub) == 32

        # Derive shared secret
        shared_secret = pkcs11_backend.ecdh_derive(peer_pub, key_label="lxmf-enc")

        assert isinstance(shared_secret, bytes)
        assert len(shared_secret) == 32

    def test_ecdh_derive_with_34_byte_ec_point(self, pkcs11_backend):
        """ECDH derivation accepts 34-byte DER-encoded EC_POINT."""
        from reticulum_pkcs11_identity.backend import raw_to_ec_point

        # Generate a peer's public key point and convert to EC_POINT
        peer_pub = pkcs11_backend.get_public_key_bytes(key_label="lxmf-enc")
        ec_point = raw_to_ec_point(peer_pub)
        assert len(ec_point) == 34

        # Derive shared secret using EC_POINT format
        shared_secret = pkcs11_backend.ecdh_derive(ec_point, key_label="lxmf-enc")

        assert isinstance(shared_secret, bytes)
        assert len(shared_secret) == 32

    def test_ecdh_derive_same_peer_produces_same_secret(self, pkcs11_backend):
        """ECDH with same peer produces same shared secret (deterministic)."""
        peer_pub = pkcs11_backend.get_public_key_bytes(key_label="lxmf-enc")

        secret1 = pkcs11_backend.ecdh_derive(peer_pub, key_label="lxmf-enc")
        secret2 = pkcs11_backend.ecdh_derive(peer_pub, key_label="lxmf-enc")

        assert secret1 == secret2

    def test_sign_nonexistent_key_raises_key_not_found(self, pkcs11_backend):
        """Sign with nonexistent key label raises PKCS11KeyNotFoundError."""
        with pytest.raises(PKCS11KeyNotFoundError, match="not found|No such key"):
            pkcs11_backend.sign(b"test", key_label="nonexistent-key")

    def test_get_public_key_bytes_nonexistent_key_raises_key_not_found(self, pkcs11_backend):
        """get_public_key_bytes for nonexistent key raises PKCS11KeyNotFoundError."""
        with pytest.raises(PKCS11KeyNotFoundError, match="not found|No such key"):
            pkcs11_backend.get_public_key_bytes(key_label="nonexistent-key")

    def test_ecdh_derive_nonexistent_key_raises_key_not_found(self, pkcs11_backend):
        """ECDH derive with nonexistent key raises PKCS11KeyNotFoundError."""
        peer_pub = b"\x04\x20" + b"\xAA" * 32
        with pytest.raises(PKCS11KeyNotFoundError, match="not found|No such key"):
            pkcs11_backend.ecdh_derive(peer_pub, key_label="nonexistent-key")


@pytest.mark.backend
@pytest.mark.keygen
class TestBackendKeyGeneration:
    """Test key generation on a real PKCS#11 token."""

    def test_generate_ed25519_keypair_creates_key(self, pkcs11_backend):
        """Generate Ed25519 keypair creates both private and public keys."""
        label = "test-ed25519-key"
        pkcs11_backend.generate_ed25519_keypair(label=label)

        # Verify the public key can be retrieved
        pub_key = pkcs11_backend.get_public_key_bytes(key_label=label)
        assert isinstance(pub_key, bytes)
        assert len(pub_key) == 32

    def test_generate_x25519_keypair_creates_key(self, pkcs11_backend):
        """Generate X25519 keypair creates both private and public keys."""
        label = "test-x25519-key"
        pkcs11_backend.generate_x25519_keypair(label=label)

        # Verify the public key can be retrieved
        pub_key = pkcs11_backend.get_public_key_bytes(key_label=label)
        assert isinstance(pub_key, bytes)
        assert len(pub_key) == 32

    def test_generated_ed25519_key_can_sign(self, pkcs11_backend):
        """Generated Ed25519 key can be used for signing."""
        label = "test-ed25519-sign"
        pkcs11_backend.generate_ed25519_keypair(label=label)

        # Sign a message using the generated key
        message = b"Test message"
        signature = pkcs11_backend.sign(message, key_label=label)

        assert isinstance(signature, bytes)
        assert len(signature) == 64

    def test_generated_x25519_key_can_derive(self, pkcs11_backend):
        """Generated X25519 key can be used for ECDH derivation."""
        label = "test-x25519-derive"
        pkcs11_backend.generate_x25519_keypair(label=label)

        # Get a peer's public key
        peer_pub = pkcs11_backend.get_public_key_bytes(key_label="lxmf-enc")

        # Derive shared secret using the generated key
        shared_secret = pkcs11_backend.ecdh_derive(peer_pub, key_label=label)

        assert isinstance(shared_secret, bytes)
        assert len(shared_secret) == 32


@pytest.mark.backend
@pytest.mark.recovery
class TestBackendSessionRecovery:
    """Test that operations recover from session loss."""

    def test_sign_after_session_reopen(self, pkcs11_backend):
        """Sign succeeds after explicitly reopening session."""
        # Close session
        pkcs11_backend.close()
        assert pkcs11_backend.lifecycle_state.value == "no_session"

        # Reopen session
        pkcs11_backend.open_session(pin="1234")
        assert pkcs11_backend.lifecycle_state.value == "active_session"

        # Sign should succeed
        message = b"After reopen"
        signature = pkcs11_backend.sign(message, key_label="lxmf-sign")
        assert len(signature) == 64

    def test_ecdh_after_session_reopen(self, pkcs11_backend):
        """ECDH succeeds after explicitly reopening session."""
        # Close session
        pkcs11_backend.close()

        # Reopen session
        pkcs11_backend.open_session(pin="1234")

        # ECDH should succeed
        peer_pub = b"\x04\x20" + b"\xAA" * 32
        shared_secret = pkcs11_backend.ecdh_derive(peer_pub, key_label="lxmf-enc")
        assert len(shared_secret) == 32


@pytest.mark.backend
@pytest.mark.threading
class TestBackendThreadSafety:
    """Test thread-safe access to cryptographic operations."""

    def test_concurrent_sign_operations(self, pkcs11_backend):
        """Multiple threads can sign concurrently."""
        import threading

        results = {}
        errors = {}

        def _sign_in_thread(thread_id):
            try:
                message = f"Thread {thread_id}".encode()
                results[thread_id] = pkcs11_backend.sign(
                    message, key_label="lxmf-sign"
                )
            except Exception as e:
                errors[thread_id] = str(e)

        threads = [threading.Thread(target=_sign_in_thread, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(results) == 5
        # Each thread should produce a unique signature (different message)
        assert len(set(results.values())) == 5

    def test_concurrent_get_public_key(self, pkcs11_backend):
        """Multiple threads can retrieve public key concurrently."""
        import threading

        results = {}
        errors = {}

        def _get_key_in_thread(thread_id):
            try:
                results[thread_id] = pkcs11_backend.get_public_key_bytes(
                    key_label="lxmf-sign"
                )
            except Exception as e:
                errors[thread_id] = str(e)

        threads = [threading.Thread(target=_get_key_in_thread, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(results) == 5
        # All threads should get the same public key
        assert len(set(results.values())) == 1
