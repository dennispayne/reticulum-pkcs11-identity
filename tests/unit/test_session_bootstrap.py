"""Unit tests for the plug-in / session bootstrap orchestration.

These exercise the branching logic with injected classifications, a fake
backend, and fake prompt callbacks -- no PKCS#11 token required.
"""

import pytest

from reticulum_pkcs11_identity.exceptions import PKCS11LoginError
from reticulum_pkcs11_identity import session_bootstrap as sb
from reticulum_pkcs11_identity.session_bootstrap import (
    BootstrapOutcome,
    TokenClassification,
    TokenStatus,
    bootstrap_session,
)

MODULE = "fake-module.so"


def _never(*_args, **_kwargs):
    raise AssertionError("callback should not have been called")


class FakeBackend:
    """Records open_session calls and simulates success/failure."""

    def __init__(self, *, error: Exception | None = None):
        self._error = error
        self.open_calls = 0
        self.opened_with = []
        self.closed = False

    def open_session(self, pin=None, **_kwargs):
        self.open_calls += 1
        self.opened_with.append(pin)
        if self._error is not None:
            raise self._error

    def close(self):
        self.closed = True


def _factory_returning(backend: FakeBackend):
    def factory(**_kwargs):
        return backend
    return factory


def _classification(status: TokenStatus, **kwargs) -> TokenClassification:
    return TokenClassification(status=status, token_label="YubiKey PIV #1", **kwargs)


# --- recognition-only outcomes (no prompts expected) ------------------------

def test_no_token():
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.ABSENT),
        pin_callback=_never,
        confirm_provision_callback=_never,
        management_key_callback=_never,
    )
    assert result.outcome is BootstrapOutcome.NO_TOKEN
    assert result.backend is None


def test_pin_locked():
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.PIN_LOCKED),
        pin_callback=_never,
        confirm_provision_callback=_never,
        management_key_callback=_never,
    )
    assert result.outcome is BootstrapOutcome.PIN_LOCKED


def test_pin_final_try_refuses_to_prompt():
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.PIN_FINAL_TRY),
        pin_callback=_never,  # must NOT be called
        confirm_provision_callback=_never,
        management_key_callback=_never,
    )
    assert result.outcome is BootstrapOutcome.PIN_FINAL_TRY


# --- returning user -> PIN -> activate --------------------------------------

def test_returning_activate_success():
    backend = FakeBackend()
    result = bootstrap_session(
        MODULE,
        classification=_classification(
            TokenStatus.RETURNING_USER, identity_hash=b"\x11" * 16
        ),
        pin_callback=lambda c: "123456",
        confirm_provision_callback=_never,
        management_key_callback=_never,
        backend_factory=_factory_returning(backend),
    )
    assert result.outcome is BootstrapOutcome.ACTIVATED
    assert result.backend is backend
    assert backend.open_calls == 1
    assert backend.opened_with == ["123456"]


def test_returning_pin_cancelled():
    backend = FakeBackend()
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.RETURNING_USER),
        pin_callback=lambda c: None,  # user cancelled
        confirm_provision_callback=_never,
        management_key_callback=_never,
        backend_factory=_factory_returning(backend),
    )
    assert result.outcome is BootstrapOutcome.CANCELLED
    assert backend.open_calls == 0


def test_returning_incorrect_pin_does_not_retry():
    backend = FakeBackend(error=PKCS11LoginError("Incorrect PIN"))
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.RETURNING_USER),
        pin_callback=lambda c: "000000",
        confirm_provision_callback=_never,
        management_key_callback=_never,
        backend_factory=_factory_returning(backend),
    )
    assert result.outcome is BootstrapOutcome.PIN_INCORRECT
    # Critical: exactly one attempt, never a retry loop.
    assert backend.open_calls == 1


def test_returning_pin_locked_during_open():
    backend = FakeBackend(
        error=PKCS11LoginError("PIN is locked; token may need to be reset")
    )
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.RETURNING_USER),
        pin_callback=lambda c: "000000",
        confirm_provision_callback=_never,
        management_key_callback=_never,
        backend_factory=_factory_returning(backend),
    )
    assert result.outcome is BootstrapOutcome.PIN_LOCKED
    assert backend.open_calls == 1


# --- new user -> confirm -> management key -> provision ---------------------

def test_new_user_declined_makes_no_changes():
    calls = []
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.NEW_USER),
        pin_callback=_never,
        confirm_provision_callback=lambda c: False,  # declined
        management_key_callback=_never,  # must NOT be reached
        provisioner=lambda **k: calls.append(k) or True,
    )
    assert result.outcome is BootstrapOutcome.PROVISION_DECLINED
    assert calls == []  # provisioner never invoked


def test_new_user_management_key_cancelled():
    calls = []
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.NEW_USER),
        pin_callback=_never,
        confirm_provision_callback=lambda c: True,
        management_key_callback=lambda c: None,  # cancelled at admin key
        provisioner=lambda **k: calls.append(k) or True,
    )
    assert result.outcome is BootstrapOutcome.CANCELLED
    assert calls == []


def test_new_user_provisioned(monkeypatch):
    calls = []

    def fake_provisioner(**kwargs):
        calls.append(kwargs)
        return True

    # After provisioning, re-recognition should now see a returning identity.
    monkeypatch.setattr(
        sb, "classify_token",
        lambda *_a, **_k: _classification(
            TokenStatus.RETURNING_USER, has_sign_key=True, has_enc_key=True
        ),
    )

    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.NEW_USER),
        pin_callback=_never,
        confirm_provision_callback=lambda c: True,
        management_key_callback=lambda c: "010203040506070801020304050607080102030405060708",
        provisioner=fake_provisioner,
    )
    assert result.outcome is BootstrapOutcome.PROVISIONED
    assert len(calls) == 1
    assert calls[0]["management_key"] == "010203040506070801020304050607080102030405060708"
    # Re-classification flowed through to the result.
    assert result.classification.status is TokenStatus.RETURNING_USER


def test_new_user_blank_management_key_uses_token_default():
    calls = []

    def fake_provisioner(**kwargs):
        calls.append(kwargs)
        return True

    bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.NEW_USER),
        pin_callback=_never,
        confirm_provision_callback=lambda c: True,
        management_key_callback=lambda c: "",  # blank -> token default
        provisioner=fake_provisioner,
    )
    assert calls[0]["management_key"] is None


def test_new_user_provision_failure():
    result = bootstrap_session(
        MODULE,
        classification=_classification(TokenStatus.NEW_USER),
        pin_callback=_never,
        confirm_provision_callback=lambda c: True,
        management_key_callback=lambda c: "deadbeef",
        provisioner=lambda **k: False,  # provisioning failed
    )
    assert result.outcome is BootstrapOutcome.PROVISION_FAILED


# --- ykman provisioner (subprocess mocked) ----------------------------------

def test_provisioner_missing_ykman(monkeypatch):
    monkeypatch.setattr(sb, "_find_ykman", lambda: None)
    assert sb.provision_identity_via_ykman(management_key="aa") is False


def test_provisioner_runs_both_keygens(monkeypatch):
    monkeypatch.setattr(sb, "_find_ykman", lambda: "ykman")
    invocations = []

    class _Done:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **_kwargs):
        invocations.append(cmd)
        return _Done()

    monkeypatch.setattr(sb.subprocess, "run", fake_run)

    ok = sb.provision_identity_via_ykman(management_key="abcd")
    assert ok is True
    # One ed25519 keygen + one x25519 keygen, into 9a and 9d respectively.
    assert len(invocations) == 2
    assert ["-a", "ed25519"] == invocations[0][4:6]
    assert invocations[0][-2] == "9a"
    assert ["-a", "x25519"] == invocations[1][4:6]
    assert invocations[1][-2] == "9d"
    # Management key forwarded.
    assert "-m" in invocations[0] and "abcd" in invocations[0]


def test_provisioner_keygen_failure_returns_false(monkeypatch):
    monkeypatch.setattr(sb, "_find_ykman", lambda: "ykman")

    class _Fail:
        returncode = 1
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(sb.subprocess, "run", lambda cmd, **k: _Fail())
    assert sb.provision_identity_via_ykman(management_key="abcd") is False
