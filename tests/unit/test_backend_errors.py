"""
Tests for PKCS11Backend error paths and edge cases that do not require
a real PKCS#11 token — they rely entirely on mocked objects or simple
data validation.
"""

import threading
import unittest.mock as mock

import pkcs11
import pytest

from reticulum_pkcs11_identity.backend import (
    PKCS11Backend,
    SessionLifecycle,
    _ec_point_to_raw,
    raw_to_ec_point,
)
from reticulum_pkcs11_identity.exceptions import (
    PKCS11BackendError,
    PKCS11SessionError,
)


# ---------------------------------------------------------------------------
# EC point helper errors
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestECPointConversion:
    def test_ec_point_to_raw_too_short_raises(self):
        with pytest.raises(PKCS11BackendError, match="Unexpected EC_POINT"):
            _ec_point_to_raw(b"\x00" * 5)

    def test_ec_point_to_raw_bad_prefix_raises(self):
        # 34 bytes but wrong prefix bytes
        with pytest.raises(PKCS11BackendError, match="Unexpected EC_POINT"):
            _ec_point_to_raw(b"\xFF\xFF" + b"\xAB" * 32)

    def test_raw_to_ec_point_wrong_length_raises(self):
        with pytest.raises(PKCS11BackendError, match="Expected 32-byte"):
            raw_to_ec_point(b"\x00" * 10)

    def test_raw_to_ec_point_wrong_length_31_raises(self):
        with pytest.raises(PKCS11BackendError, match="Expected 32-byte"):
            raw_to_ec_point(b"\x00" * 31)


# ---------------------------------------------------------------------------
# PKCS11Backend.__init__ validation
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestBackendInit:
    def test_init_requires_token_label_or_slot_id(self):
        with pytest.raises(PKCS11BackendError, match="Either token_label or slot_id"):
            PKCS11Backend(module_path="/some/path.so")

    def test_init_bad_module_path_raises(self):
        with pytest.raises(PKCS11BackendError, match="Failed to load PKCS#11 module"):
            PKCS11Backend(module_path="/nonexistent/libpkcs11.so", token_label="test")

    def test_init_with_slot_id_but_no_token_label_accepted(self):
        # Should fail at module load, not at validation
        with pytest.raises(PKCS11BackendError, match="Failed to load PKCS#11 module"):
            PKCS11Backend(module_path="/nonexistent/lib.so", slot_id=0)


# ---------------------------------------------------------------------------
# close() method
# ---------------------------------------------------------------------------

def _make_bare_backend():
    backend = PKCS11Backend.__new__(PKCS11Backend)
    backend._lock = threading.RLock()
    backend._session = None
    backend._state = SessionLifecycle.NO_SESSION
    backend._pin = None
    backend._pin_callback = None
    backend._prompt = None
    backend._token_label = None
    backend._slot_id = None
    backend._bound_token_fingerprint = None
    return backend


@pytest.mark.backend
class TestBackendClose:
    def test_close_calls_session_close_and_clears_state(self):
        backend = _make_bare_backend()
        fake_session = mock.MagicMock()
        backend._session = fake_session
        backend._state = SessionLifecycle.ACTIVE_SESSION

        backend.close()

        fake_session.close.assert_called_once()
        assert backend._session is None
        assert backend._state == SessionLifecycle.NO_SESSION

    def test_close_when_already_none_is_idempotent(self):
        backend = _make_bare_backend()
        backend.close()  # should not raise
        assert backend._session is None

    def test_close_swallows_exception_from_session_close(self):
        backend = _make_bare_backend()
        fake_session = mock.MagicMock()
        fake_session.close.side_effect = RuntimeError("token removed")
        backend._session = fake_session
        backend._state = SessionLifecycle.ACTIVE_SESSION

        backend.close()  # must not propagate the RuntimeError

        assert backend._session is None
        assert backend._state == SessionLifecycle.NO_SESSION


# ---------------------------------------------------------------------------
# _require_session
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestRequireSession:
    def test_require_session_raises_when_not_open(self):
        backend = _make_bare_backend()

        with pytest.raises(PKCS11SessionError, match="not open"):
            backend._require_session()


# ---------------------------------------------------------------------------
# _resolve_pin (static)
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestResolvePin:
    def test_direct_pin_returned(self):
        assert PKCS11Backend._resolve_pin("secret", None, None) == "secret"

    def test_callback_invoked(self):
        cb = mock.MagicMock(return_value="from-callback")
        result = PKCS11Backend._resolve_pin(None, cb, None)
        assert result == "from-callback"
        cb.assert_called_once()

    def test_getpass_called_with_supplied_prompt(self):
        with mock.patch("getpass.getpass", return_value="gp-pin") as gp:
            result = PKCS11Backend._resolve_pin(None, None, "Enter PIN: ")
        assert result == "gp-pin"
        gp.assert_called_once_with("Enter PIN: ")

    def test_getpass_called_with_default_prompt(self):
        with mock.patch("getpass.getpass", return_value="gp-pin") as gp:
            result = PKCS11Backend._resolve_pin(None, None, None)
        assert result == "gp-pin"
        gp.assert_called_once_with("PKCS#11 user PIN: ")


# ---------------------------------------------------------------------------
# ecdh_derive — invalid peer_public_point
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestECDHInvalidPoint:
    def test_ecdh_derive_wrong_size_raises(self):
        backend = _make_bare_backend()
        backend._session = mock.MagicMock()
        backend._state = SessionLifecycle.ACTIVE_SESSION

        with pytest.raises(PKCS11BackendError, match="peer_public_point must be"):
            backend.ecdh_derive(b"\x00" * 20, key_label="lxmf-enc")

    def test_ecdh_derive_34_bytes_wrong_prefix_raises(self):
        backend = _make_bare_backend()
        backend._session = mock.MagicMock()
        backend._state = SessionLifecycle.ACTIVE_SESSION

        with pytest.raises(PKCS11BackendError, match="peer_public_point must be"):
            backend.ecdh_derive(b"\xFF\xFF" + b"\x00" * 32, key_label="lxmf-enc")


# ---------------------------------------------------------------------------
# _get_token_for_session
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestGetTokenForSession:
    def _make(self, candidates, *, token_label=None, bound_fp=None):
        backend = _make_bare_backend()
        backend._token_label = token_label
        backend._bound_token_fingerprint = bound_fp
        backend._find_token_candidates = lambda: candidates
        return backend

    def test_no_candidates_sets_session_lost(self):
        backend = self._make([])
        with pytest.raises(PKCS11SessionError):
            backend._get_token_for_session()
        assert backend._state == SessionLifecycle.SESSION_LOST

    def test_no_candidates_with_token_label_mentions_label(self):
        backend = self._make([], token_label="MyToken")
        with pytest.raises(PKCS11SessionError, match="MyToken"):
            backend._get_token_for_session()

    def test_single_candidate_returned(self):
        tok = object()
        result = self._make([(1, tok)])._get_token_for_session()
        assert result is tok

    def test_bound_fingerprint_match_returns_token(self):
        class _Tok:
            label = "T"
            serial = "S"
            slot = type("SL", (), {"slot_id": 1})()

        tok = _Tok()
        backend = self._make([(1, tok)], bound_fp=("T", "S", 1))
        assert backend._get_token_for_session() is tok

    def test_bound_fingerprint_mismatch_raises_token_changed(self):
        class _Tok:
            label = "T"
            serial = "DIFFERENT"
            slot = type("SL", (), {"slot_id": 1})()

        tok = _Tok()
        backend = self._make([(1, tok)], bound_fp=("T", "ORIGINAL", 1))
        with pytest.raises(PKCS11SessionError, match="different PKCS#11 token"):
            backend._get_token_for_session()
        assert backend._state == SessionLifecycle.TOKEN_CHANGED


# ---------------------------------------------------------------------------
# _choose_token_candidate — invalid callback result
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestChooseTokenCandidate:
    def test_invalid_callback_index_raises(self):
        backend = _make_bare_backend()
        candidates = [(1, object()), (2, object())]

        with pytest.raises(PKCS11SessionError, match="Invalid PKCS#11 token selection"):
            backend._choose_token_candidate(candidates, lambda _: 99)

    def test_negative_callback_index_raises(self):
        backend = _make_bare_backend()
        candidates = [(1, object())]

        with pytest.raises(PKCS11SessionError, match="Invalid PKCS#11 token selection"):
            backend._choose_token_candidate(candidates, lambda _: -1)

    def test_valid_callback_index_returns_token(self):
        backend = _make_bare_backend()
        tok_a = object()
        tok_b = object()
        candidates = [(1, tok_a), (2, tok_b)]

        result = backend._choose_token_candidate(candidates, lambda _: 1)
        assert result is tok_b


# ---------------------------------------------------------------------------
# _find_key — MultipleObjectsReturned
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestFindKeyErrors:
    def test_multiple_objects_returned_raises_backend_error(self):
        from pkcs11 import ObjectClass, KeyType

        backend = _make_bare_backend()
        fake_session = mock.MagicMock()
        fake_session.get_key.side_effect = pkcs11.exceptions.MultipleObjectsReturned()

        with pytest.raises(PKCS11BackendError, match="Multiple keys"):
            backend._find_key(
                fake_session,
                ObjectClass.PRIVATE_KEY,
                KeyType.EC_EDWARDS,
                key_label="duplicate-key",
                key_id=None,
            )

    def test_find_key_with_key_id_passes_id_kwarg(self):
        from pkcs11 import ObjectClass, KeyType

        backend = _make_bare_backend()
        fake_session = mock.MagicMock()
        fake_key = mock.MagicMock()
        fake_session.get_key.return_value = fake_key
        key_id = b"\x01\x02\x03"

        result = backend._find_key(
            fake_session,
            ObjectClass.PUBLIC_KEY,
            KeyType.EC_EDWARDS,
            key_label=None,
            key_id=key_id,
        )

        assert result is fake_key
        assert fake_session.get_key.call_args.kwargs["id"] == key_id


# ---------------------------------------------------------------------------
# generate_ed25519_keypair / generate_x25519_keypair — exception paths
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestKeyGenerationErrors:
    def _backend_with_session(self):
        backend = _make_bare_backend()
        fake_session = mock.MagicMock()
        fake_session.generate_keypair.side_effect = RuntimeError("device error")
        backend._session = fake_session
        backend._state = SessionLifecycle.ACTIVE_SESSION
        return backend

    def test_generate_ed25519_keypair_exception_raises_backend_error(self):
        from reticulum_pkcs11_identity.exceptions import PKCS11BackendError
        backend = self._backend_with_session()
        with pytest.raises(PKCS11BackendError, match="Ed25519 key generation failed"):
            backend.generate_ed25519_keypair("test-key")

    def test_generate_x25519_keypair_exception_raises_backend_error(self):
        from reticulum_pkcs11_identity.exceptions import PKCS11BackendError
        backend = self._backend_with_session()
        with pytest.raises(PKCS11BackendError, match="X25519 key generation failed"):
            backend.generate_x25519_keypair("test-key")


# ---------------------------------------------------------------------------
# sign / ecdh_derive / get_public_key_bytes — outer exception wrappers
# ---------------------------------------------------------------------------

def _backend_with_failing_find_key(exc_to_raise):
    """Return a backend whose _find_key always raises exc_to_raise."""
    backend = _make_bare_backend()
    backend._session = mock.MagicMock()
    backend._state = SessionLifecycle.ACTIVE_SESSION
    backend._find_key = mock.MagicMock(side_effect=exc_to_raise)
    return backend


@pytest.mark.backend
class TestOperationOuterExceptionWrapping:
    def test_sign_non_session_failure_wrapped_as_backend_error(self):
        backend = _backend_with_failing_find_key(ValueError("unexpected"))
        with pytest.raises(PKCS11BackendError, match="Signing failed"):
            backend.sign(b"msg", key_label="lxmf-sign")

    def test_ecdh_derive_non_session_failure_wrapped_as_backend_error(self):
        backend = _backend_with_failing_find_key(ValueError("unexpected"))
        peer_point = b"\x04\x20" + b"\xAA" * 32
        with pytest.raises(PKCS11BackendError, match="ECDH derivation failed"):
            backend.ecdh_derive(peer_point, key_label="lxmf-enc")

    def test_get_public_key_bytes_generic_exception_wrapped_as_backend_error(self):
        backend = _backend_with_failing_find_key(ValueError("unexpected"))
        with pytest.raises(PKCS11BackendError, match="Could not read public key"):
            backend.get_public_key_bytes(key_label="lxmf-sign")

    def test_get_public_key_bytes_pkcs11_backend_error_re_raised(self):
        """A PKCS11BackendError from _find_key must be re-raised, not double-wrapped."""
        from reticulum_pkcs11_identity.exceptions import PKCS11BackendError as BE
        backend = _backend_with_failing_find_key(BE("bad ec point"))
        with pytest.raises(BE, match="bad ec point"):
            backend.get_public_key_bytes(key_label="lxmf-sign")


# ---------------------------------------------------------------------------
# _get_token_for_session — multiple candidates with callback
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestGetTokenForSessionMultiCandidate:
    def test_multiple_candidates_with_callback_returns_selected_token(self):
        backend = _make_bare_backend()
        tok_a = object()
        tok_b = object()
        backend._bound_token_fingerprint = None
        backend._find_token_candidates = lambda: [(1, tok_a), (2, tok_b)]

        result = backend._get_token_for_session(token_selection_callback=lambda _: 1)

        assert result is tok_b


# ---------------------------------------------------------------------------
# rebind_to_current_token
# ---------------------------------------------------------------------------

@pytest.mark.backend
class TestRebindToCurrentToken:
    def test_rebind_calls_close_then_open_session_with_force_rebind(self):
        backend = _make_bare_backend()
        backend._pin = "1234"
        backend._pin_callback = None
        backend._prompt = None

        with mock.patch.object(backend, "close") as mock_close, \
             mock.patch.object(backend, "open_session") as mock_open:
            backend.rebind_to_current_token()

        mock_close.assert_called_once()
        mock_open.assert_called_once()
        kwargs = mock_open.call_args.kwargs
        assert kwargs["force_rebind"] is True
        assert kwargs["pin"] == "1234"

    def test_rebind_uses_supplied_pin_over_stored(self):
        backend = _make_bare_backend()
        backend._pin = "old-pin"
        backend._pin_callback = None
        backend._prompt = None

        with mock.patch.object(backend, "close"), \
             mock.patch.object(backend, "open_session") as mock_open:
            backend.rebind_to_current_token(pin="new-pin")

        kwargs = mock_open.call_args.kwargs
        assert kwargs["pin"] == "new-pin"