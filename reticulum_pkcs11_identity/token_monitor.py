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

"""Token change detection and session invalidation.

Monitors PKCS#11 token state and detects changes to provider, serial numbers,
or hardware version. When changes are detected, cached sessions are invalidated
to force re-authentication on the next operation.

Design:
  - Polls token state on demand (no background thread by default)
  - Can be called before each identity operation or periodically
  - On detection of change: logs clearly, invalidates sessions
  - Next identity operation fails with guidance to re-authenticate
"""

import logging
from typing import Optional, Dict, Tuple, Any

import pkcs11

from .exceptions import PKCS11BackendError, PKCS11SessionError

logger = logging.getLogger(__name__)


class TokenMonitorError(PKCS11BackendError):
    """Raised when token monitoring fails."""
    pass


class TokenMonitor:
    """
    Monitors PKCS#11 token state for changes.

    Detects when the provider or tokens change and coordinates session
    invalidation with the backend. Can be polled on-demand or run as a
    background daemon (optional).

    Thread-safe via internal lock.
    """

    def __init__(self, backend):
        """
        Initialize token monitor.

        :param backend: PKCS11Backend instance to monitor.
        """
        self._backend = backend
        # Share the backend's reentrant lock rather than using a private one.
        # Probing token state enters the PKCS#11 module via C_GetSlotList /
        # C_GetTokenInfo (see get_provider_state), while the backend's crypto
        # enters it via C_Sign / C_DeriveKey. PKCS#11 modules such as SoftHSM2
        # are not safe against two threads being *inside the module* at once:
        # concurrent native calls corrupt the module's heap (observed as
        # "free(): invalid pointer" / "unaligned fastbin" -> SIGSEGV) or
        # deadlock on an internal mutex (-> hang). A single shared lock
        # serializes ALL native access; the RLock preserves same-thread
        # reentrancy (detect_changes -> get_provider_state).
        self._lock = backend._lock
        self._previous_state: Optional[Dict[str, Any]] = None
        self._on_token_change_callback = None

    def get_provider_state(self) -> Dict[str, Any]:
        """
        Get current provider and token state.

        Returns a dictionary with:
        - provider_id: Module path or name
        - token_label: Token label
        - token_serials: Set of serial numbers of available tokens
        - slot_ids: Set of available slot IDs
        - bound_fingerprint: Current bound token fingerprint (if any)

        This is a snapshot of the current state. Safe to call even if
        no session is open.

        :returns: State dictionary
        :raises TokenMonitorError: If state cannot be determined
        """
        try:
            state = {
                "provider_id": self._backend._lib._name if hasattr(self._backend._lib, "_name") else str(self._backend._lib),
                "token_label": self._backend._token_label,
                "token_serials": set(),
                "slot_ids": set(),
                "bound_fingerprint": self._backend._bound_token_fingerprint,
            }

            # Enumerate available tokens/slots. Hold the shared backend lock so
            # this native PKCS#11 access (C_GetSlotList / C_GetTokenInfo) cannot
            # overlap a concurrent C_Sign / C_DeriveKey running on another
            # thread, which would corrupt the module or deadlock it.
            try:
                with self._lock:
                    slots = list(self._backend._lib.get_slots(token_present=True))
                    for slot in slots:
                        state["slot_ids"].add(slot.slot_id)
                        try:
                            token = slot.get_token()
                            serial = (getattr(token, "serial", "") or "").strip()
                            if serial:
                                state["token_serials"].add(serial)
                        except pkcs11.exceptions.TokenNotPresent:
                            pass
                        except Exception:
                            pass
            except Exception as exc:
                logger.debug(f"Could not enumerate slots: {exc}")

            return state
        except Exception as exc:
            raise TokenMonitorError(f"Could not get provider state: {exc}") from exc

    def detect_changes(self) -> Tuple[bool, Optional[str]]:
        """
        Detect if token or provider state has changed.

        Compares current state to previously recorded state. On first call,
        records current state and returns no change. On subsequent calls,
        detects additions, removals, or serial changes.

        :returns: Tuple of (changed: bool, reason: Optional[str]).
                  changed=True means token/provider state has changed.
                  reason is a human-readable message if changed.
        """
        with self._lock:
            current = self.get_provider_state()

            if self._previous_state is None:
                self._previous_state = current
                return False, None

            prev = self._previous_state
            current_serials = current["token_serials"]
            prev_serials = prev["token_serials"]
            current_slots = current["slot_ids"]
            prev_slots = prev["slot_ids"]

            # Check for serial changes
            removed_serials = prev_serials - current_serials
            added_serials = current_serials - prev_serials

            if removed_serials:
                reason = f"Token(s) removed: {', '.join(sorted(removed_serials))}"
                self._previous_state = current
                return True, reason

            if added_serials:
                reason = f"Token(s) added: {', '.join(sorted(added_serials))}"
                self._previous_state = current
                return True, reason

            # Check for slot changes
            removed_slots = prev_slots - current_slots
            added_slots = current_slots - prev_slots

            if removed_slots:
                reason = f"Slot(s) removed: {', '.join(map(str, sorted(removed_slots)))}"
                self._previous_state = current
                return True, reason

            if added_slots:
                reason = f"Slot(s) added: {', '.join(map(str, sorted(added_slots)))}"
                self._previous_state = current
                return True, reason

            # Check for provider changes
            if current["provider_id"] != prev["provider_id"]:
                reason = f"Provider changed: {prev['provider_id']} -> {current['provider_id']}"
                self._previous_state = current
                return True, reason

            return False, None

    def invalidate_sessions(self) -> None:
        """
        Invalidate cached sessions in the backend.

        Called when token change is detected. Clears any open session and
        marks it as lost so the next operation will fail gracefully or
        attempt to reopen with the new token.

        Thread-safe and idempotent.
        """
        with self._lock:
            try:
                if self._backend._session is not None:
                    try:
                        self._backend._session.close()
                    except Exception:
                        pass
                    self._backend._session = None

                # Mark session as lost to force re-authentication on next operation
                from .backend import SessionLifecycle
                self._backend._state = SessionLifecycle.TOKEN_CHANGED

                logger.warning(
                    "Token change detected. PKCS#11 session invalidated. "
                    "Please re-authenticate with PIN or physical card on next operation."
                )
            except Exception as exc:
                logger.error(f"Failed to invalidate sessions: {exc}")

    def check_and_invalidate(self) -> bool:
        """
        Check for token changes and invalidate if needed.

        Convenience method that calls detect_changes() and invalidates
        sessions if a change is detected.

        :returns: True if change was detected and sessions invalidated,
                  False if no change.
        """
        changed, reason = self.detect_changes()
        if changed:
            logger.warning(f"Token change detected: {reason}")
            self.invalidate_sessions()
            return True
        return False

    def set_on_token_change_callback(self, callback=None) -> None:
        """
        Set optional callback to invoke when token change is detected.

        The callback receives (reason: str) and may be used to notify
        the application or perform cleanup.

        :param callback: Callable(reason: str) or None to remove callback.
        """
        with self._lock:
            self._on_token_change_callback = callback

    def _invoke_callback(self, reason: str) -> None:
        """Invoke the token change callback if set."""
        with self._lock:
            callback = self._on_token_change_callback
        if callback is not None:
            try:
                callback(reason)
            except Exception as exc:
                logger.error(f"Token change callback failed: {exc}")
