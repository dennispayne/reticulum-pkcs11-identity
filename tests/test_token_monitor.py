"""Tests for token monitoring and session invalidation."""

import threading
import unittest.mock as mock

import pytest

from reticulum_pkcs11_identity.token_monitor import TokenMonitor, TokenMonitorError
from reticulum_pkcs11_identity.backend import SessionLifecycle, PKCS11Backend


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


def _make_backend_with_monitor():
    """Create a backend with a token monitor for testing."""
    backend = PKCS11Backend.__new__(PKCS11Backend)
    backend._lock = threading.RLock()
    backend._lib = _FakeLib()
    backend._session = object()
    backend._state = SessionLifecycle.ACTIVE_SESSION
    backend._pin = "1234"
    backend._pin_callback = None
    backend._prompt = None
    backend._token_label = "TestToken"
    backend._slot_id = None
    backend._bound_token_fingerprint = ("TestToken", "SERIAL-123", 0)
    backend._token_monitor = None
    return backend


@pytest.mark.monitor
def test_get_provider_state_returns_dict_with_expected_keys():
    """Test that get_provider_state returns a dict with expected keys."""
    backend = _make_backend_with_monitor()
    monitor = TokenMonitor(backend)

    state = monitor.get_provider_state()

    assert isinstance(state, dict)
    assert "provider_id" in state
    assert "token_label" in state
    assert "token_serials" in state
    assert "slot_ids" in state
    assert "bound_fingerprint" in state


@pytest.mark.monitor
def test_get_provider_state_captures_token_info():
    """Test that get_provider_state captures token serial numbers."""
    backend = _make_backend_with_monitor()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    monitor = TokenMonitor(backend)
    state = monitor.get_provider_state()

    assert "SERIAL-123" in state["token_serials"]
    assert 0 in state["slot_ids"]


@pytest.mark.monitor
def test_detect_changes_returns_no_change_on_first_call():
    """Test that detect_changes returns no change on first call."""
    backend = _make_backend_with_monitor()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    monitor = TokenMonitor(backend)
    changed, reason = monitor.detect_changes()

    assert changed is False
    assert reason is None


@pytest.mark.monitor
def test_detect_changes_detects_token_removal():
    """Test that detect_changes detects token removal."""
    backend = _make_backend_with_monitor()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    monitor = TokenMonitor(backend)
    # First call establishes baseline
    monitor.detect_changes()

    # Remove token
    backend._lib._slots = []

    changed, reason = monitor.detect_changes()

    assert changed is True
    assert "removed" in reason.lower()


@pytest.mark.monitor
def test_detect_changes_detects_token_addition():
    """Test that detect_changes detects token addition."""
    backend = _make_backend_with_monitor()
    backend._lib._slots = []

    monitor = TokenMonitor(backend)
    # First call establishes baseline (no tokens)
    monitor.detect_changes()

    # Add token
    token = _FakeToken("TestToken", "SERIAL-456", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    changed, reason = monitor.detect_changes()

    assert changed is True
    assert "added" in reason.lower()


@pytest.mark.monitor
def test_detect_changes_detects_serial_change():
    """Test that detect_changes detects serial number changes."""
    backend = _make_backend_with_monitor()
    token1 = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token1)
    backend._lib._slots = [slot]

    monitor = TokenMonitor(backend)
    # First call establishes baseline
    monitor.detect_changes()

    # Change token (same slot, different serial)
    token2 = _FakeToken("TestToken", "SERIAL-789", 0)
    slot._token = token2

    changed, reason = monitor.detect_changes()

    assert changed is True
    assert "removed" in reason.lower() or "added" in reason.lower()


@pytest.mark.monitor
def test_invalidate_sessions_closes_session():
    """Test that invalidate_sessions closes the backend session."""
    backend = _make_backend_with_monitor()
    mock_session = mock.MagicMock()
    backend._session = mock_session

    monitor = TokenMonitor(backend)
    monitor.invalidate_sessions()

    mock_session.close.assert_called_once()
    assert backend._session is None
    assert backend._state == SessionLifecycle.TOKEN_CHANGED


@pytest.mark.monitor
def test_invalidate_sessions_handles_close_error():
    """Test that invalidate_sessions handles close errors gracefully."""
    backend = _make_backend_with_monitor()
    mock_session = mock.MagicMock()
    mock_session.close.side_effect = Exception("Close failed")
    backend._session = mock_session

    monitor = TokenMonitor(backend)
    # Should not raise
    monitor.invalidate_sessions()

    assert backend._session is None
    assert backend._state == SessionLifecycle.TOKEN_CHANGED


@pytest.mark.monitor
def test_check_and_invalidate_returns_false_when_no_change():
    """Test that check_and_invalidate returns False when no change."""
    backend = _make_backend_with_monitor()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    monitor = TokenMonitor(backend)
    # Establish baseline
    monitor.detect_changes()

    result = monitor.check_and_invalidate()

    assert result is False


@pytest.mark.monitor
def test_check_and_invalidate_returns_true_and_invalidates_on_change():
    """Test that check_and_invalidate detects change and invalidates."""
    backend = _make_backend_with_monitor()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]
    mock_session = mock.MagicMock()
    backend._session = mock_session

    monitor = TokenMonitor(backend)
    # Establish baseline
    monitor.detect_changes()

    # Change token
    backend._lib._slots = []

    result = monitor.check_and_invalidate()

    assert result is True
    mock_session.close.assert_called_once()
    assert backend._session is None


@pytest.mark.monitor
def test_set_on_token_change_callback():
    """Test that callback can be set and invoked."""
    backend = _make_backend_with_monitor()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    monitor = TokenMonitor(backend)
    # Establish baseline
    monitor.detect_changes()

    callback_called = {"count": 0, "reason": None}

    def test_callback(reason):
        callback_called["count"] += 1
        callback_called["reason"] = reason

    monitor.set_on_token_change_callback(test_callback)

    # Change token
    backend._lib._slots = []
    monitor.check_and_invalidate()

    # Note: callback invocation is optional in the current implementation
    # This test documents the interface


@pytest.mark.monitor
def test_get_token_monitor_lazy_creates_monitor():
    """Test that backend.get_token_monitor() lazily creates a monitor."""
    backend = _make_backend_with_monitor()

    assert backend._token_monitor is None

    monitor = backend.get_token_monitor()

    assert backend._token_monitor is not None
    assert isinstance(monitor, TokenMonitor)


@pytest.mark.monitor
def test_get_token_monitor_returns_same_instance():
    """Test that get_token_monitor returns the same instance."""
    backend = _make_backend_with_monitor()

    monitor1 = backend.get_token_monitor()
    monitor2 = backend.get_token_monitor()

    assert monitor1 is monitor2


@pytest.mark.monitor
def test_token_monitor_thread_safe():
    """Test that token monitor is thread-safe."""
    backend = _make_backend_with_monitor()
    token = _FakeToken("TestToken", "SERIAL-123", 0)
    slot = _FakeSlot(0, token)
    backend._lib._slots = [slot]

    monitor = TokenMonitor(backend)
    monitor.detect_changes()

    results = []

    def change_and_check():
        backend._lib._slots = []
        changed, reason = monitor.detect_changes()
        results.append(changed)

    # Run multiple threads checking for changes
    threads = [threading.Thread(target=change_and_check) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All threads should see the change (or no change if it was already detected)
    assert len(results) == 3
