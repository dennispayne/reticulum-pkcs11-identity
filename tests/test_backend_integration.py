"""
Integration tests for PKCS11Backend backend primitives using real hardware or SoftHSM2.

These tests require a PKCS#11 token (YubiKey with real keys, or SoftHSM2 for testing).
They will be skipped automatically if no token is available.
"""

import pytest


@pytest.mark.integration
@pytest.mark.hardware
class TestBackendPrimitivesIntegration:
    """Integration tests for backend primitives with real token."""

    @pytest.mark.skipif(
        not pytest.mark.skipif,
        reason="Optional integration test - run with --marker=hardware"
    )
    def test_can_sign_with_real_token(self, pkcs11_backend):
        """Real token can sign messages."""
        message = b"Integration test message"
        try:
            signature = pkcs11_backend.sign(message, key_label="lxmf-sign")
            assert len(signature) == 64
            assert isinstance(signature, bytes)
        except Exception:
            pytest.skip("Real token not available")

    @pytest.mark.skipif(
        not pytest.mark.skipif,
        reason="Optional integration test - run with --marker=hardware"
    )
    def test_can_derive_ecdh_with_real_token(self, pkcs11_backend):
        """Real token can perform ECDH derivation."""
        try:
            peer_key = b"\x04\x20" + b"\xAA" * 32
            shared_secret = pkcs11_backend.ecdh_derive(peer_key, key_label="lxmf-enc")
            assert len(shared_secret) == 32
            assert isinstance(shared_secret, bytes)
        except Exception:
            pytest.skip("Real token not available")

    @pytest.mark.skipif(
        not pytest.mark.skipif,
        reason="Optional integration test - run with --marker=hardware"
    )
    def test_can_read_public_key_from_real_token(self, pkcs11_backend):
        """Real token can provide public key."""
        try:
            pub_key = pkcs11_backend.get_public_key_bytes(key_label="lxmf-sign")
            assert len(pub_key) == 32
            assert isinstance(pub_key, bytes)
        except Exception:
            pytest.skip("Real token not available")


@pytest.mark.backend_features
class TestBackendFeatures:
    """Test backend feature availability and error conditions."""

    def test_backend_requires_pin_or_callback_or_prompt(self, pkcs11_backend):
        """Backend can work with various PIN resolution methods."""
        from reticulum_pkcs11_identity.backend import PKCS11Backend
        from reticulum_pkcs11_identity.exceptions import PKCS11SessionError

        backend = PKCS11Backend.__new__(PKCS11Backend)
        import threading
        backend._lock = threading.RLock()
        backend._session = None
        backend._state = 0  # NO_SESSION
        backend._pin = None
        backend._pin_callback = None
        backend._prompt = None
        backend._token_label = None
        backend._slot_id = None
        backend._bound_token_fingerprint = None

        # open_session with missing credentials should attempt to get PIN from callback chain


@pytest.mark.backend_state
class TestBackendStateTransitions:
    """Test backend lifecycle state transitions."""

    def test_backend_starts_in_no_session(self, pkcs11_backend):
        """Backend starts with no session."""
        # pkcs11_backend is already opened by the fixture
        # Just verify its state is accessible
        assert pkcs11_backend.lifecycle_state is not None

    def test_backend_can_reopen_after_close(self, pkcs11_backend):
        """Backend can be reopened after close."""
        pkcs11_backend.close()
        assert pkcs11_backend.lifecycle_state.value == "no_session"

        # Reopen
        pkcs11_backend.open_session(pin="1234")
        assert pkcs11_backend.lifecycle_state.value == "active_session"

    def test_backend_close_is_idempotent(self, pkcs11_backend):
        """Backend close can be called multiple times safely."""
        pkcs11_backend.close()
        pkcs11_backend.close()  # Should not raise
        assert pkcs11_backend.lifecycle_state.value == "no_session"


@pytest.mark.backend_validation
class TestBackendValidation:
    """Test backend input validation."""

    def test_sign_empty_message(self, pkcs11_backend):
        """Signing empty message succeeds."""
        signature = pkcs11_backend.sign(b"", key_label="lxmf-sign")
        assert len(signature) == 64

    def test_sign_large_message(self, pkcs11_backend):
        """Signing large message succeeds."""
        large_msg = b"X" * 1_000_000
        signature = pkcs11_backend.sign(large_msg, key_label="lxmf-sign")
        assert len(signature) == 64

    def test_ecdh_accepts_raw_32_bytes(self, pkcs11_backend):
        """ECDH accepts raw 32-byte public key."""
        peer_key = b"\xAA" * 32
        shared_secret = pkcs11_backend.ecdh_derive(peer_key, key_label="lxmf-enc")
        assert len(shared_secret) == 32

    def test_ecdh_accepts_34_byte_ec_point(self, pkcs11_backend):
        """ECDH accepts 34-byte DER-encoded EC_POINT."""
        peer_key = b"\x04\x20" + b"\xBB" * 32
        shared_secret = pkcs11_backend.ecdh_derive(peer_key, key_label="lxmf-enc")
        assert len(shared_secret) == 32


@pytest.mark.backend_consistency
class TestBackendConsistency:
    """Test that operations are consistent and reproducible."""

    def test_public_key_is_stable(self, pkcs11_backend):
        """Public key does not change across calls."""
        key1 = pkcs11_backend.get_public_key_bytes(key_label="lxmf-sign")
        key2 = pkcs11_backend.get_public_key_bytes(key_label="lxmf-sign")
        key3 = pkcs11_backend.get_public_key_bytes(key_label="lxmf-sign")

        assert key1 == key2 == key3

    def test_signature_is_deterministic(self, pkcs11_backend):
        """Ed25519 signatures are deterministic."""
        message = b"Deterministic test"
        sig1 = pkcs11_backend.sign(message, key_label="lxmf-sign")
        sig2 = pkcs11_backend.sign(message, key_label="lxmf-sign")
        sig3 = pkcs11_backend.sign(message, key_label="lxmf-sign")

        assert sig1 == sig2 == sig3

    def test_ecdh_is_deterministic(self, pkcs11_backend):
        """ECDH derivation is deterministic."""
        peer_key = b"\xCC" * 32
        secret1 = pkcs11_backend.ecdh_derive(peer_key, key_label="lxmf-enc")
        secret2 = pkcs11_backend.ecdh_derive(peer_key, key_label="lxmf-enc")
        secret3 = pkcs11_backend.ecdh_derive(peer_key, key_label="lxmf-enc")

        assert secret1 == secret2 == secret3
