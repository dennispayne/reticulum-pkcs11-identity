"""
Tests for PKCS11PIVBackend PIV-specific functionality.

Tests verify PIV slot awareness, session management, and key operations
specific to PIV tokens (YubiKey, etc.).
"""

import threading
import pytest
import unittest.mock as mock

import pkcs11

from reticulum_pkcs11_identity.backend_piv import (
    PKCS11PIVBackend,
    SessionLifecycle,
    PIVSlot,
    _ec_point_to_raw,
    _raw_to_ec_point,
)
from reticulum_pkcs11_identity.exceptions import (
    PKCS11BackendError,
    PKCS11KeyNotFoundError,
    PKCS11LoginError,
    PKCS11SessionError,
    SlotNotFoundError,
)


def _make_backend_with_session(session=None, state=SessionLifecycle.ACTIVE_SESSION):
    """Create a bare PIVBackend wired with a (mock) session for method tests."""
    backend = PKCS11PIVBackend.__new__(PKCS11PIVBackend)
    backend._lock = threading.RLock()
    backend._session = session if session is not None else mock.MagicMock()
    backend._state = state
    backend._pin = "123456"
    backend._slot_id = None
    backend._token_label = None
    backend._bound_token = None
    backend._lib = mock.MagicMock()
    return backend


def _fake_pub_key(raw=b"\xAB" * 32):
    """Return a mock public-key object indexable by Attribute.EC_POINT."""
    from pkcs11 import Attribute

    obj = mock.MagicMock()
    obj.__getitem__.side_effect = lambda attr: (
        b"\x04\x20" + raw if attr == Attribute.EC_POINT else None
    )
    return obj


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


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendOpenSession:
    """Test open_session authentication paths."""

    def _backend_with_token(self, token):
        backend = _make_backend_with_session(state=SessionLifecycle.NO_SESSION)
        backend._session = None
        backend._find_token = mock.MagicMock(return_value=token)
        return backend

    def test_open_session_already_active_returns_early(self):
        backend = _make_backend_with_session(state=SessionLifecycle.ACTIVE_SESSION)
        backend._find_token = mock.MagicMock()
        backend.open_session("123456")
        backend._find_token.assert_not_called()

    def test_open_session_success(self):
        token = mock.MagicMock()
        token.label = "YubiKey"
        token.serial = b"123"
        session = mock.MagicMock()
        token.open.return_value = session
        backend = self._backend_with_token(token)

        backend.open_session("999999")

        assert backend._state == SessionLifecycle.ACTIVE_SESSION
        assert backend._session is session
        assert backend._pin == "999999"
        token.open.assert_called_once_with(rw=True, user_pin="999999")

    def test_open_session_requires_explicit_pin(self):
        # No PIN is ever defaulted in source; opening without one must fail.
        token = mock.MagicMock()
        token.label = "YubiKey"
        token.serial = b"123"
        token.open.return_value = mock.MagicMock()
        backend = self._backend_with_token(token)

        with pytest.raises(PKCS11LoginError, match="PIN is required"):
            backend.open_session()

    def test_open_session_pin_locked(self):
        token = mock.MagicMock()
        token.open.side_effect = pkcs11.exceptions.PinLocked()
        backend = self._backend_with_token(token)

        with pytest.raises(PKCS11LoginError, match="PIN is locked"):
            backend.open_session("123456")
        assert backend._state == SessionLifecycle.SESSION_LOST

    def test_open_session_pin_incorrect(self):
        token = mock.MagicMock()
        token.open.side_effect = pkcs11.exceptions.PinIncorrect()
        backend = self._backend_with_token(token)

        with pytest.raises(PKCS11LoginError, match="Incorrect PIN"):
            backend.open_session("000000")

    def test_open_session_generic_auth_failure(self):
        token = mock.MagicMock()
        token.open.side_effect = RuntimeError("boom")
        backend = self._backend_with_token(token)

        with pytest.raises(PKCS11LoginError, match="Failed to authenticate"):
            backend.open_session("123456")


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendFindToken:
    """Test _find_token slot/label resolution."""

    def _make(self, slots, slot_id=None, token_label=None):
        backend = PKCS11PIVBackend.__new__(PKCS11PIVBackend)
        backend._lock = threading.RLock()
        backend._slot_id = slot_id
        backend._token_label = token_label
        backend._lib = mock.MagicMock()
        backend._lib.get_slots.return_value = slots
        return backend

    def test_find_token_by_label(self):
        token = mock.MagicMock()
        token.label = "YubiKey"
        slot = mock.MagicMock()
        slot.slot_id = 0
        slot.get_token.return_value = token
        backend = self._make([slot], token_label="YubiKey")

        assert backend._find_token() is token

    def test_find_token_label_mismatch_raises(self):
        token = mock.MagicMock()
        token.label = "OtherKey"
        slot = mock.MagicMock()
        slot.slot_id = 0
        slot.get_token.return_value = token
        backend = self._make([slot], token_label="YubiKey")

        with pytest.raises(SlotNotFoundError):
            backend._find_token()

    def test_find_token_slot_id_filter(self):
        token = mock.MagicMock()
        token.label = "YubiKey"
        slot0 = mock.MagicMock()
        slot0.slot_id = 0
        slot1 = mock.MagicMock()
        slot1.slot_id = 1
        slot1.get_token.return_value = token
        backend = self._make([slot0, slot1], slot_id=1)

        assert backend._find_token() is token
        slot0.get_token.assert_not_called()

    def test_find_token_skips_broken_slot(self):
        bad_slot = mock.MagicMock()
        bad_slot.slot_id = 0
        bad_slot.get_token.side_effect = RuntimeError("dead")
        good_token = mock.MagicMock()
        good_token.label = "YubiKey"
        good_slot = mock.MagicMock()
        good_slot.slot_id = 1
        good_slot.get_token.return_value = good_token
        backend = self._make([bad_slot, good_slot])

        assert backend._find_token() is good_token

    def test_find_token_enumerate_failure(self):
        backend = PKCS11PIVBackend.__new__(PKCS11PIVBackend)
        backend._lock = threading.RLock()
        backend._slot_id = None
        backend._token_label = None
        backend._lib = mock.MagicMock()
        backend._lib.get_slots.side_effect = RuntimeError("usb error")

        with pytest.raises(PKCS11SessionError, match="Failed to enumerate slots"):
            backend._find_token()

    def test_find_token_none_present(self):
        backend = self._make([])
        with pytest.raises(SlotNotFoundError):
            backend._find_token()


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendRequireSession:
    """Test _require_session and recovery."""

    def test_require_session_active(self):
        session = mock.MagicMock()
        backend = _make_backend_with_session(session=session)
        assert backend._require_session() is session

    def test_require_session_no_session_raises(self):
        backend = _make_backend_with_session(state=SessionLifecycle.NO_SESSION)
        backend._session = None
        with pytest.raises(PKCS11SessionError, match="No active session"):
            backend._require_session()

    def test_require_session_recovers_on_loss(self):
        backend = _make_backend_with_session(state=SessionLifecycle.SESSION_LOST)
        backend._session = None
        recovered = mock.MagicMock()

        def fake_open(pin):
            backend._session = recovered
            backend._state = SessionLifecycle.ACTIVE_SESSION

        backend.open_session = mock.MagicMock(side_effect=fake_open)
        assert backend._require_session() is recovered
        backend.open_session.assert_called_once_with("123456")


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendSign:
    """Test sign()."""

    def test_sign_success(self):
        session = mock.MagicMock()
        session.get_objects.return_value = [mock.MagicMock()]
        session.sign.return_value = b"signature"
        backend = _make_backend_with_session(session=session)

        result = backend.sign(b"msg", key_label="app-sign")

        assert result == b"signature"
        session.sign.assert_called_once()

    def test_sign_key_not_found(self):
        session = mock.MagicMock()
        session.get_objects.return_value = []
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11KeyNotFoundError, match="Ed25519 key not found"):
            backend.sign(b"msg", key_label="missing")

    def test_sign_wraps_errors(self):
        session = mock.MagicMock()
        session.get_objects.return_value = [mock.MagicMock()]
        session.sign.side_effect = RuntimeError("hw fault")
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11BackendError, match="Sign operation failed"):
            backend.sign(b"msg", key_label="app-sign")


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendGetPublicKey:
    """Test get_public_key()."""

    def test_get_public_key_success(self):
        session = mock.MagicMock()
        session.get_objects.return_value = [_fake_pub_key(b"\x11" * 32)]
        backend = _make_backend_with_session(session=session)

        result = backend.get_public_key(key_label="app-sign")
        assert result == b"\x11" * 32

    def test_get_public_key_not_found(self):
        session = mock.MagicMock()
        session.get_objects.return_value = []
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11KeyNotFoundError, match="Public key not found"):
            backend.get_public_key(key_label="missing")

    def test_get_public_key_wraps_errors(self):
        session = mock.MagicMock()
        session.get_objects.side_effect = RuntimeError("read fault")
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11BackendError, match="Key retrieval failed"):
            backend.get_public_key(key_label="app-sign")


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendKeyGen:
    """Test generate_ed25519_keypair / generate_x25519_keypair."""

    def test_generate_ed25519_success(self):
        session = mock.MagicMock()
        pub = _fake_pub_key(b"\x22" * 32)
        session.generate_keypair.return_value = (pub, mock.MagicMock())
        backend = _make_backend_with_session(session=session)

        pub_bytes, priv = backend.generate_ed25519_keypair("app-sign")
        assert pub_bytes == b"\x22" * 32
        assert priv is None

    def test_generate_ed25519_failure(self):
        session = mock.MagicMock()
        session.generate_keypair.side_effect = RuntimeError("gen fail")
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11BackendError, match="Ed25519 key generation failed"):
            backend.generate_ed25519_keypair("app-sign")

    def test_generate_x25519_success(self):
        session = mock.MagicMock()
        pub = _fake_pub_key(b"\x33" * 32)
        session.generate_keypair.return_value = (pub, mock.MagicMock())
        backend = _make_backend_with_session(session=session)

        pub_bytes, priv = backend.generate_x25519_keypair("app-enc", key_id=b"id")
        assert pub_bytes == b"\x33" * 32
        assert priv is None

    def test_generate_x25519_failure(self):
        session = mock.MagicMock()
        session.generate_keypair.side_effect = RuntimeError("gen fail")
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11BackendError, match="X25519 key generation failed"):
            backend.generate_x25519_keypair("app-enc")


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendEcdhDerive:
    """Test ecdh_derive()."""

    def test_ecdh_derive_key_not_found(self):
        session = mock.MagicMock()
        session.get_objects.return_value = []
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11KeyNotFoundError, match="ECDH key not found"):
            backend.ecdh_derive("missing", b"\x55" * 32)

    def test_ecdh_derive_wraps_errors(self):
        session = mock.MagicMock()
        session.get_objects.return_value = [mock.MagicMock()]
        session.derive_key.side_effect = RuntimeError("derive fault")
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11BackendError, match="ECDH derivation failed"):
            backend.ecdh_derive("app-enc", b"\x55" * 32)


@pytest.mark.backend_piv
@pytest.mark.backend
class TestPIVBackendEnsureKeysForApp:
    """Test ensure_keys_for_app()."""

    def test_keys_already_exist(self):
        # Lookup order: ed-priv, x-priv, ed-pub, x-pub
        session = mock.MagicMock()
        priv = mock.MagicMock()
        ed_pub = _fake_pub_key(b"\x66" * 32)
        x_pub = _fake_pub_key(b"\x77" * 32)
        session.get_objects.side_effect = [[priv], [priv], [ed_pub], [x_pub]]
        backend = _make_backend_with_session(session=session)

        ed_bytes, x_bytes = backend.ensure_keys_for_app("myapp")
        assert ed_bytes == b"\x66" * 32
        assert x_bytes == b"\x77" * 32
        session.generate_keypair.assert_not_called()

    def test_keys_generated_when_missing(self):
        # ed-priv empty, x-priv empty -> generate both, then ed-pub, x-pub
        session = mock.MagicMock()
        ed_pub = _fake_pub_key(b"\x66" * 32)
        x_pub = _fake_pub_key(b"\x77" * 32)
        session.get_objects.side_effect = [[], [], [ed_pub], [x_pub]]
        backend = _make_backend_with_session(session=session)

        ed_bytes, x_bytes = backend.ensure_keys_for_app("myapp")
        assert ed_bytes == b"\x66" * 32
        assert x_bytes == b"\x77" * 32
        assert session.generate_keypair.call_count == 2

    def test_public_key_missing_after_generation(self):
        # ed-priv empty, x-priv empty -> generate, then ed-pub empty -> raise
        session = mock.MagicMock()
        session.get_objects.side_effect = [[], [], []]
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11KeyNotFoundError, match="not found after generation"):
            backend.ensure_keys_for_app("myapp")

    def test_ensure_keys_wraps_errors(self):
        session = mock.MagicMock()
        session.get_objects.side_effect = RuntimeError("token fault")
        backend = _make_backend_with_session(session=session)

        with pytest.raises(PKCS11BackendError):
            backend.ensure_keys_for_app("myapp")
