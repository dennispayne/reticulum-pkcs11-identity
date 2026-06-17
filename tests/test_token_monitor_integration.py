"""Integration tests for token monitor with identity operations."""

import threading
import unittest.mock as mock

import pytest

from reticulum_pkcs11_identity.backend import PKCS11Backend, SessionLifecycle
from reticulum_pkcs11_identity.identity import make_lxmf_identity_class


class _FakeLib:
    def __init__(self, name="test-lib"):
        self._name = name
        self._slots = []

    def get_slots(self, token_present=True):
        assert token_present is True
        return self._slots


class _FakeToken:
    def __init__(self, label, serial, slot_id):
        self.label = label
        self.serial = serial
        self.slot = type("SlotRef", (), {"slot_id": slot_id})()


class _FakeSlot:
    def __init__(self, slot_id, token):
        self.slot_id = slot_id
        self._token = token

    def get_token(self):
        return self._token


class _FakeSession:
    def close(self):
        pass

    def get_key(self, **kwargs):
        raise Exception("Key not found")


def _make_backend_for_identity_test():
    """Create a backend for identity testing."""
    backend = PKCS11Backend.__new__(PKCS11Backend)
    backend._lock = threading.RLock()
    backend._lib = _FakeLib()
    backend._session = _FakeSession()
    backend._state = SessionLifecycle.ACTIVE_SESSION
    backend._pin = "1234"
    backend._pin_callback = None
    backend._prompt = None
    backend._token_label = "TestToken"
    backend._slot_id = None
    backend._bound_token_fingerprint = ("TestToken", "SERIAL-123", 0)
    backend._token_monitor = None
    return backend


@pytest.mark.integration
def test_identity_check_token_state_method_exists():
    """Test that identity has _check_token_state method."""
    backend = _make_backend_for_identity_test()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    # Create a hardware identity class
    IdentityClass = make_lxmf_identity_class(
        backend=backend,
        sign_key_label="lxmf-sign",
        enc_key_label="lxmf-enc",
    )

    # Create identity instance with mocked key loading
    identity = IdentityClass.__new__(IdentityClass)
    identity._backend = backend
    identity._sign_key_label = "lxmf-sign"
    identity._sign_key_id = None
    identity._enc_key_label = "lxmf-enc"
    identity._enc_key_id = None
    identity._is_local_hardware = True

    # Test that _check_token_state exists and can be called
    assert hasattr(identity, "_check_token_state")
    # Should not raise on normal token state
    identity._check_token_state()


@pytest.mark.integration
def test_identity_detects_token_change_in_sign():
    """Test that sign operation detects token change."""
    backend = _make_backend_for_identity_test()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    # Create a hardware identity class
    IdentityClass = make_lxmf_identity_class(
        backend=backend,
        sign_key_label="lxmf-sign",
        enc_key_label="lxmf-enc",
    )

    # Create identity instance with mocked key loading
    identity = IdentityClass.__new__(IdentityClass)
    identity._backend = backend
    identity._sign_key_label = "lxmf-sign"
    identity._sign_key_id = None
    identity._enc_key_label = "lxmf-enc"
    identity._enc_key_id = None
    identity._is_local_hardware = True
    identity.sig_prv = None

    # Mock the backend.sign method to avoid actual PKCS#11 calls
    backend.sign = mock.MagicMock(return_value=b"\xAA" * 64)

    # Establish baseline token state
    monitor = backend.get_token_monitor()
    monitor.detect_changes()

    # Change token (remove it)
    backend._lib._slots = []

    # Attempt to sign - should detect token change
    with pytest.raises(RuntimeError, match="token has changed"):
        identity.sign(b"test message")


@pytest.mark.integration
def test_identity_detects_token_change_in_decrypt():
    """Test that decrypt operation detects token change."""
    backend = _make_backend_for_identity_test()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    # Create a hardware identity class
    IdentityClass = make_lxmf_identity_class(
        backend=backend,
        sign_key_label="lxmf-sign",
        enc_key_label="lxmf-enc",
    )

    # Create identity instance with mocked key loading
    identity = IdentityClass.__new__(IdentityClass)
    identity._backend = backend
    identity._sign_key_label = "lxmf-sign"
    identity._sign_key_id = None
    identity._enc_key_label = "lxmf-enc"
    identity._enc_key_id = None
    identity._is_local_hardware = True

    # Establish baseline token state
    monitor = backend.get_token_monitor()
    monitor.detect_changes()

    # Change token (remove it)
    backend._lib._slots = []

    # Create a ciphertext token (64 bytes of ephemeral pub key + 32 bytes encrypted)
    ciphertext_token = b"\x00" * 32 + b"\x11" * 32

    # Attempt to decrypt - should detect token change
    with pytest.raises(RuntimeError, match="token has changed"):
        identity.decrypt(ciphertext_token)


@pytest.mark.integration
def test_token_monitor_invalidates_session_on_change():
    """Test that token monitor invalidates sessions when change is detected."""
    backend = _make_backend_for_identity_test()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]
    mock_session = mock.MagicMock()
    backend._session = mock_session

    monitor = backend.get_token_monitor()
    # Establish baseline
    monitor.detect_changes()

    # Change token
    backend._lib._slots = []

    # Check and invalidate
    result = monitor.check_and_invalidate()

    assert result is True
    mock_session.close.assert_called_once()
    assert backend._session is None
    assert backend._state == SessionLifecycle.TOKEN_CHANGED


@pytest.mark.integration
def test_token_monitor_tracks_state_across_identity_operations():
    """Test that token monitor state is tracked correctly across operations."""
    backend = _make_backend_for_identity_test()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    # Create a hardware identity class
    IdentityClass = make_lxmf_identity_class(
        backend=backend,
        sign_key_label="lxmf-sign",
        enc_key_label="lxmf-enc",
    )

    # Create identity instance
    identity = IdentityClass.__new__(IdentityClass)
    identity._backend = backend
    identity._sign_key_label = "lxmf-sign"
    identity._sign_key_id = None
    identity._enc_key_label = "lxmf-enc"
    identity._enc_key_id = None
    identity._is_local_hardware = True

    # Check token state - should be OK
    identity._check_token_state()

    # Get monitor and check state
    monitor = backend.get_token_monitor()
    changed, reason = monitor.detect_changes()
    assert changed is False

    # Token is removed
    backend._lib._slots = []

    # Check again - should detect change
    changed, reason = monitor.detect_changes()
    assert changed is True
    assert "removed" in reason.lower()

    # Monitor state should be updated
    assert monitor._previous_state is not None
    # The previous state should now show the token was removed


@pytest.mark.integration
def test_token_change_logs_clear_message():
    """Test that token changes are logged with clear messages."""
    backend = _make_backend_for_identity_test()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    monitor = backend.get_token_monitor()
    monitor.detect_changes()

    # Remove token
    backend._lib._slots = []

    changed, reason = monitor.detect_changes()
    assert changed is True
    assert "removed" in reason.lower()

    # Invalidate
    with mock.patch("reticulum_pkcs11_identity.token_monitor.logger") as mock_logger:
        monitor.invalidate_sessions()
        # Should log a warning about token change
        mock_logger.warning.assert_called()
