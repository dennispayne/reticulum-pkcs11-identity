import threading

import pkcs11
import pytest

from reticulum_pkcs11_identity.backend import PKCS11Backend, SessionLifecycle
from reticulum_pkcs11_identity.exceptions import PKCS11SessionError


class _FakeKey:
    def __init__(self):
        self.calls = 0

    def sign(self, _data, mechanism=None):
        self.calls += 1
        if self.calls == 1:
            raise pkcs11.exceptions.SessionClosed()
        return b"\xAA" * 64


class _FakeToken:
    def __init__(self, label, serial, slot_id):
        self.label = label
        self.serial = serial
        self.slot = type("SlotRef", (), {"slot_id": slot_id})()
        self.last_open_pin = None
        self._open_result = object()

    def open(self, rw=True, user_pin=None):
        self.last_open_pin = user_pin
        return self._open_result


class _FakeSlot:
    def __init__(self, slot_id, token):
        self.slot_id = slot_id
        self._token = token

    def get_token(self):
        return self._token


class _FakeLib:
    def __init__(self, slots):
        self._slots = slots

    def get_slots(self, token_present=True):
        assert token_present is True
        return self._slots


def _make_backend():
    backend = PKCS11Backend.__new__(PKCS11Backend)
    backend._lock = threading.RLock()
    backend._session = object()
    backend._state = SessionLifecycle.ACTIVE_SESSION
    backend._pin = "1234"
    backend._pin_callback = None
    backend._prompt = None
    backend._token_label = "Match"
    backend._slot_id = None
    backend._bound_token_fingerprint = None
    return backend


def test_sign_recovers_after_session_lost():
    backend = _make_backend()
    fake_key = _FakeKey()
    backend._find_key = lambda *args, **kwargs: fake_key
    reopened = {"count": 0}

    def _reopen():
        reopened["count"] += 1
        backend._session = object()
        backend._state = SessionLifecycle.ACTIVE_SESSION

    backend._reopen_session = _reopen

    sig = backend.sign(b"message", key_label="rns-sign")

    assert sig == b"\xAA" * 64
    assert reopened["count"] == 1
    assert backend.lifecycle_state == SessionLifecycle.ACTIVE_SESSION


def test_token_change_sets_state_and_fails():
    backend = _make_backend()
    backend._bound_token_fingerprint = ("Match", "SERIAL-A", 1)

    with pytest.raises(PKCS11SessionError, match="does not match"):
        backend._bind_or_validate_token_binding(("Match", "SERIAL-B", 1))

    assert backend.lifecycle_state == SessionLifecycle.TOKEN_CHANGED


def test_find_candidates_sorted_deterministically():
    backend = _make_backend()
    token_a = _FakeToken("Match", "S2", 2)
    token_b = _FakeToken("Match", "S1", 1)
    backend._lib = _FakeLib(
        [
            _FakeSlot(2, token_a),
            _FakeSlot(1, token_b),
        ]
    )

    candidates = backend._find_token_candidates()

    assert [slot_id for slot_id, _ in candidates] == [1, 2]


def test_multiple_candidates_use_callback_selection():
    backend = _make_backend()
    candidates = [
        (1, _FakeToken("Match", "S1", 1)),
        (2, _FakeToken("Match", "S2", 2)),
    ]

    selected = backend._choose_token_candidate(
        candidates,
        token_selection_callback=lambda _candidates: 1,
    )

    assert selected.serial == "S2"


def test_open_session_skips_pin_resolution_when_token_absent():
    backend = _make_backend()
    backend._session = None
    backend._state = SessionLifecycle.NO_SESSION
    backend._lib = _FakeLib([])

    pin_resolved = {"called": False}

    def _fake_resolve_pin(*_args, **_kwargs):
        pin_resolved["called"] = True
        return "1234"

    backend._resolve_pin = _fake_resolve_pin

    with pytest.raises(PKCS11SessionError, match="Failed to open PKCS#11 session"):
        backend.open_session()

    assert pin_resolved["called"] is False


def test_open_session_caches_resolved_pin_for_recovery():
    backend = _make_backend()
    backend._session = None
    backend._state = SessionLifecycle.NO_SESSION

    token = _FakeToken("Match", "SERIAL-1", 1)
    backend._lib = _FakeLib([_FakeSlot(1, token)])

    backend.open_session(pin_callback=lambda: "2468")

    assert backend._pin == "2468"
    assert token.last_open_pin == "2468"
    assert backend.lifecycle_state == SessionLifecycle.ACTIVE_SESSION
