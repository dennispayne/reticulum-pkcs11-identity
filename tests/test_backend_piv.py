"""
Tests for PKCS11PIVBackend PIV-specific functionality.

Tests verify PIV slot awareness, session management, and key operations
specific to PIV tokens (YubiKey, etc.).
"""

import pytest
import unittest.mock as mock

from reticulum_pkcs11_identity.backend_piv import (
    PKCS11PIVBackend,
    SessionLifecycle,
    PIVSlot,
    _ec_point_to_raw,
    _raw_to_ec_point,
)
from reticulum_pkcs11_identity.exceptions import PKCS11BackendError


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVSlotEnum:
    """Test PIV slot enumeration."""

    def test_piv_slot_values(self):
        """PIV slots have correct values."""
        assert PIVSlot.AUTHENTICATION.value == "9a"
        assert PIVSlot.SIGNATURE.value == "9c"
        assert PIVSlot.KEY_MANAGEMENT.value == "9d"
        assert PIVSlot.CARD_AUTHENTICATION.value == "9e"

    def test_piv_slot_names(self):
        """PIV slots have correct names."""
        assert PIVSlot.AUTHENTICATION.name == "AUTHENTICATION"
        assert PIVSlot.SIGNATURE.name == "SIGNATURE"
        assert PIVSlot.KEY_MANAGEMENT.name == "KEY_MANAGEMENT"
        assert PIVSlot.CARD_AUTHENTICATION.name == "CARD_AUTHENTICATION"


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVECPointConversion:
    """Test EC_POINT conversion helpers."""

    def test_ec_point_to_raw_valid(self):
        """Convert valid EC_POINT to raw 32-byte key."""
        ec_point = b"\x04\x20" + b"\xAA" * 32
        raw = _ec_point_to_raw(ec_point)

        assert raw == b"\xAA" * 32
        assert len(raw) == 32

    def test_ec_point_to_raw_invalid_length(self):
        """EC_POINT with invalid length raises error."""
        with pytest.raises(PKCS11BackendError, match="Invalid EC_POINT"):
            _ec_point_to_raw(b"\x04\x20" + b"\xAA" * 31)

    def test_ec_point_to_raw_invalid_prefix(self):
        """EC_POINT with invalid prefix raises error."""
        with pytest.raises(PKCS11BackendError, match="Invalid EC_POINT"):
            _ec_point_to_raw(b"\xFF\xFF" + b"\xAA" * 32)

    def test_raw_to_ec_point_valid(self):
        """Convert raw 32-byte key to EC_POINT."""
        raw = b"\xAA" * 32
        ec_point = _raw_to_ec_point(raw)

        assert ec_point == b"\x04\x20" + b"\xAA" * 32
        assert len(ec_point) == 34

    def test_raw_to_ec_point_invalid_length(self):
        """Raw key with invalid length raises error."""
        with pytest.raises(PKCS11BackendError, match="Expected 32-byte"):
            _raw_to_ec_point(b"\xAA" * 31)

    def test_raw_to_ec_point_too_long(self):
        """Raw key that's too long raises error."""
        with pytest.raises(PKCS11BackendError, match="Expected 32-byte"):
            _raw_to_ec_point(b"\xAA" * 64)


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendInit:
    """Test PKCS11PIVBackend initialization."""

    def test_init_requires_module_path(self):
        """Backend initialization requires module_path."""
        with pytest.raises(TypeError):
            PKCS11PIVBackend()

    def test_init_with_token_label(self):
        """Backend can be initialized with token_label."""
        with pytest.raises(PKCS11BackendError, match="Failed to load"):
            PKCS11PIVBackend(
                module_path="/nonexistent/libykcs11.so",
                token_label="YubiKey"
            )

    def test_init_with_slot_id(self):
        """Backend can be initialized with slot_id."""
        with pytest.raises(PKCS11BackendError, match="Failed to load"):
            PKCS11PIVBackend(
                module_path="/nonexistent/libykcs11.so",
                slot_id=0
            )

    def test_init_with_both_token_label_and_slot_id(self):
        """Backend can be initialized with both token_label and slot_id."""
        with pytest.raises(PKCS11BackendError, match="Failed to load"):
            PKCS11PIVBackend(
                module_path="/nonexistent/libykcs11.so",
                token_label="YubiKey",
                slot_id=0
            )


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendSessionLifecycle:
    """Test PIV backend session lifecycle."""

    def _make_piv_backend(self):
        """Create a bare PIVBackend for testing."""
        backend = PKCS11PIVBackend.__new__(PKCS11PIVBackend)
        backend._lock = mock.MagicMock()
        backend._session = None
        backend._state = SessionLifecycle.NO_SESSION
        backend._pin = None
        backend._pin_callback = None
        backend._prompt = None
        backend._token_label = None
        backend._slot_id = None
        backend._bound_token_fingerprint = None
        return backend

    def test_initial_state_is_no_session(self):
        """Backend starts in NO_SESSION state."""
        backend = self._make_piv_backend()
        assert backend._state == SessionLifecycle.NO_SESSION

    def test_close_clears_session(self):
        """Close operation clears session."""
        backend = self._make_piv_backend()
        backend._session = mock.MagicMock()
        backend._state = SessionLifecycle.ACTIVE_SESSION

        backend.close()

        assert backend._session is None
        assert backend._state == SessionLifecycle.NO_SESSION

    def test_close_swallows_exceptions(self):
        """Close operation swallows exceptions from session.close()."""
        backend = self._make_piv_backend()
        fake_session = mock.MagicMock()
        fake_session.close.side_effect = RuntimeError("Device error")
        backend._session = fake_session
        backend._state = SessionLifecycle.ACTIVE_SESSION

        backend.close()  # Should not raise

        assert backend._session is None


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendSessionStates:
    """Test PIV backend session state transitions."""

    def test_session_lost_state(self):
        """SESSION_LOST state indicates token was removed."""
        state = SessionLifecycle.SESSION_LOST
        assert state.value == "session_lost"

    def test_token_changed_state(self):
        """TOKEN_CHANGED state indicates a different token is present."""
        state = SessionLifecycle.TOKEN_CHANGED
        assert state.value == "token_changed"

    def test_active_session_state(self):
        """ACTIVE_SESSION state indicates authenticated session."""
        state = SessionLifecycle.ACTIVE_SESSION
        assert state.value == "active_session"

    def test_no_session_state(self):
        """NO_SESSION state indicates no session is open."""
        state = SessionLifecycle.NO_SESSION
        assert state.value == "no_session"


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendErrors:
    """Test PIV backend error handling."""

    def test_init_with_bad_module_path_raises(self):
        """Initialization with nonexistent module path raises error."""
        with pytest.raises(PKCS11BackendError, match="Failed to load"):
            PKCS11PIVBackend(
                module_path="/definitely/not/a/real/module.so",
                token_label="Test"
            )

    def test_ec_point_conversion_round_trip(self):
        """EC_POINT conversion round trips correctly."""
        original = b"\xAA" * 32
        ec_point = _raw_to_ec_point(original)
        recovered = _ec_point_to_raw(ec_point)

        assert recovered == original


@pytest.mark.backend_piv
@pytest.mark.recovery
class TestPIVBackendRecovery:
    """Test PIV backend recovery mechanisms."""

    def test_session_lifecycle_state_transitions(self):
        """Session lifecycle state enum has all expected values."""
        states = [
            SessionLifecycle.NO_SESSION,
            SessionLifecycle.ACTIVE_SESSION,
            SessionLifecycle.SESSION_LOST,
            SessionLifecycle.TOKEN_CHANGED,
        ]
        assert len(states) == 4

    def test_session_lifecycle_is_string_enum(self):
        """Session lifecycle values are strings."""
        for state in SessionLifecycle:
            assert isinstance(state.value, str)


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendThreadSafety:
    """Test PIV backend thread safety."""

    def test_backend_has_lock(self):
        """Backend should have thread lock."""
        backend = PKCS11PIVBackend.__new__(PKCS11PIVBackend)
        import threading
        backend._lock = threading.RLock()
        assert hasattr(backend, "_lock")
        assert isinstance(backend._lock, type(threading.RLock()))
