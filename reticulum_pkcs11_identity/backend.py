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

"""
PKCS#11 backend wrapper.

This module provides a thin, generic wrapper around the python-pkcs11 library.
It manages a single long-lived session and exposes the operations needed by
HardwareIdentity: signing (Ed25519) and ECDH key derivation (X25519).

Design goals:
  - One login per application session, never one per message.
  - No dependency on any specific hardware token.
  - Recoverable sessions: if the token is removed and reinserted the session
    is transparently reopened on the next operation.
"""

import getpass
import threading
from enum import Enum

import pkcs11
from pkcs11 import KeyType, Mechanism, ObjectClass, Attribute
from pkcs11.mechanisms import KDF

from .exceptions import (
    PKCS11BackendError,
    PKCS11KeyNotFoundError,
    PKCS11LoginError,
    PKCS11SessionError,
)

# DER-encoded OID prefix for Edwards (Ed25519) and Montgomery (X25519) curves.
# Ed25519 OID 1.3.101.112 → 06 03 2B 65 70
_ED25519_PARAMS = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
# X25519 OID 1.3.101.110  → 06 03 2B 65 6E
_X25519_PARAMS  = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])

# DER EC_POINT prefix used by PKCS#11 for 32-byte curve keys: 04 20
_EC_POINT_PREFIX = bytes([0x04, 0x20])


class SessionLifecycle(str, Enum):
    NO_SESSION = "no_session"
    ACTIVE_SESSION = "active_session"
    SESSION_LOST = "session_lost"
    TOKEN_CHANGED = "token_changed"


def _ec_point_to_raw(ec_point: bytes) -> bytes:
    """Strip the two-byte DER prefix from a 34-byte EC_POINT and return the raw 32-byte key."""
    if len(ec_point) == 34 and ec_point[:2] == _EC_POINT_PREFIX:
        return ec_point[2:]
    raise PKCS11BackendError(
        f"Unexpected EC_POINT format (length {len(ec_point)}): {ec_point.hex()}"
    )


def raw_to_ec_point(raw: bytes) -> bytes:
    """Prepend the two-byte DER prefix to a raw 32-byte key to produce a PKCS#11 EC_POINT."""
    if len(raw) != 32:
        raise PKCS11BackendError(f"Expected 32-byte raw key, got {len(raw)} bytes")
    return _EC_POINT_PREFIX + raw


class PKCS11Backend:
    """
    A thin, stateful wrapper around a single PKCS#11 session.

    The session is opened and the user is authenticated exactly once.
    All subsequent sign and ECDH derive calls reuse the same session.
    If the session is lost (e.g. token removed), it is transparently
    reopened the next time an operation is attempted.

    Thread safety: operations are serialised with a lock so the same
    backend can safely be shared across threads.
    """

    def __init__(
        self,
        module_path: str,
        token_label: str | None = None,
        slot_id: int | None = None,
    ):
        """
        :param module_path: Path to the PKCS#11 shared library (e.g. libsofthsm2.so).
        :param token_label: Label of the token to use.  Either *token_label* or
            *slot_id* must be provided.
        :param slot_id: Slot ID to use as an alternative to *token_label*.
        """
        if token_label is None and slot_id is None:
            raise PKCS11BackendError("Either token_label or slot_id must be specified")

        try:
            self._lib = pkcs11.lib(module_path)
        except Exception as exc:
            raise PKCS11BackendError(f"Failed to load PKCS#11 module '{module_path}': {exc}") from exc

        self._token_label = token_label
        self._slot_id = slot_id
        self._session: pkcs11.Session | None = None
        self._lock = threading.RLock()
        self._state = SessionLifecycle.NO_SESSION
        self._pin: str | None = None
        self._pin_callback = None
        self._prompt: str | None = None
        self._bound_token_fingerprint: tuple[str, str, int] | None = None

    @property
    def lifecycle_state(self) -> SessionLifecycle:
        return self._state

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def open_session(
        self,
        pin: str | None = None,
        pin_callback=None,
        prompt: str | None = None,
        token_selection_callback=None,
        force_rebind: bool = False,
    ) -> None:
        """
        Open a read-write PKCS#11 session and authenticate with the user PIN.

        The PIN is requested **once** via one of the following, in priority order:

        1. The *pin* argument.
        2. The callable *pin_callback()* (called without arguments, must return str).
        3. An interactive :func:`getpass.getpass` prompt.

        :param pin: PIN as a plain string, or *None*.
        :param pin_callback: Zero-argument callable that returns the PIN string.
        :param prompt: Custom prompt text for :func:`getpass.getpass`.
        :raises PKCS11LoginError: if authentication fails.
        :raises PKCS11SessionError: if the session cannot be opened.
        """
        with self._lock:
            if self._session is not None:
                return

            effective_pin = self._resolve_pin(pin, pin_callback, prompt)
            self._pin = pin
            self._pin_callback = pin_callback
            self._prompt = prompt
            try:
                token = self._get_token(token_selection_callback=token_selection_callback)
                fingerprint = self._token_fingerprint(token)
                self._bind_or_validate_token_binding(fingerprint, force_rebind=force_rebind)
                self._session = token.open(rw=True, user_pin=effective_pin)
                self._state = SessionLifecycle.ACTIVE_SESSION
            except pkcs11.exceptions.PinIncorrect as exc:
                raise PKCS11LoginError("Incorrect PIN") from exc
            except pkcs11.exceptions.PinLocked as exc:
                raise PKCS11LoginError("PIN is locked; token may need to be reset") from exc
            except pkcs11.exceptions.TokenNotPresent as exc:
                self._state = SessionLifecycle.SESSION_LOST
                raise PKCS11SessionError("PKCS#11 token is not present") from exc
            except pkcs11.exceptions.MultipleTokensReturned:
                self._state = SessionLifecycle.NO_SESSION
                raise PKCS11SessionError("Multiple matching PKCS#11 tokens found and no selection was made")
            except Exception as exc:
                self._state = SessionLifecycle.NO_SESSION
                raise PKCS11SessionError(f"Failed to open PKCS#11 session: {exc}") from exc

    def close(self) -> None:
        """Close the PKCS#11 session and release all resources."""
        with self._lock:
            if self._session is not None:
                try:
                    self._session.close()
                except Exception:
                    pass
                self._session = None
            self._state = SessionLifecycle.NO_SESSION

    # ------------------------------------------------------------------
    # Cryptographic operations
    # ------------------------------------------------------------------

    def sign(
        self,
        data: bytes,
        *,
        key_label: str | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        """
        Sign *data* using the Ed25519 (CKK_EC_EDWARDS) private key on the token.

        :param data: The message bytes to sign.
        :param key_label: PKCS#11 ``CKA_LABEL`` of the signing key.
        :param key_id: PKCS#11 ``CKA_ID`` of the signing key.
        :returns: 64-byte Ed25519 signature.
        :raises PKCS11KeyNotFoundError: if the key is not found.
        :raises PKCS11BackendError: on other PKCS#11 errors.
        """
        with self._lock:
            def _do_sign(session):
                prv = self._find_key(
                    session,
                    ObjectClass.PRIVATE_KEY,
                    KeyType.EC_EDWARDS,
                    key_label=key_label,
                    key_id=key_id,
                )
                return bytes(prv.sign(data, mechanism=Mechanism.EDDSA))
            try:
                return self._execute_with_recovery(_do_sign)
            except Exception as exc:
                raise PKCS11BackendError(f"Signing failed: {exc}") from exc

    def ecdh_derive(
        self,
        peer_public_point: bytes,
        *,
        key_label: str | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        """
        Perform an X25519 ECDH key agreement inside the token and return the
        raw 32-byte shared secret.

        The private key stays on the token; only the derived shared secret is
        extracted, which is required to complete HKDF + AES decryption in
        software.

        :param peer_public_point: 34-byte DER-encoded EC_POINT of the peer's
            ephemeral X25519 public key (``04 20`` prefix + 32 raw bytes), or a
            raw 32-byte key (the prefix is added automatically).
        :param key_label: PKCS#11 ``CKA_LABEL`` of the encryption private key.
        :param key_id: PKCS#11 ``CKA_ID`` of the encryption private key.
        :returns: 32-byte X25519 shared secret.
        :raises PKCS11KeyNotFoundError: if the key is not found.
        :raises PKCS11BackendError: on other PKCS#11 errors.
        """
        # Accept either raw 32 bytes or a full EC_POINT.
        if len(peer_public_point) == 32:
            peer_public_point = raw_to_ec_point(peer_public_point)
        elif len(peer_public_point) != 34 or peer_public_point[:2] != _EC_POINT_PREFIX:
            raise PKCS11BackendError(
                f"peer_public_point must be 32 raw bytes or 34-byte DER EC_POINT, got {len(peer_public_point)} bytes"
            )

        with self._lock:
            def _do_derive(session):
                prv = self._find_key(
                    session,
                    ObjectClass.PRIVATE_KEY,
                    KeyType.EC_EDWARDS,
                    key_label=key_label,
                    key_id=key_id,
                )
                derived = prv.derive_key(
                    KeyType.GENERIC_SECRET,
                    32 * 8,
                    mechanism_param=(KDF.NULL, None, peer_public_point),
                    mechanism=Mechanism.ECDH1_DERIVE,
                    store=False,
                    template={
                        Attribute.SENSITIVE: False,
                        Attribute.EXTRACTABLE: True,
                    },
                )
                return bytes(derived[Attribute.VALUE])
            try:
                return self._execute_with_recovery(_do_derive)
            except Exception as exc:
                raise PKCS11BackendError(f"ECDH derivation failed: {exc}") from exc

    def get_public_key_bytes(
        self,
        *,
        key_label: str | None = None,
        key_id: bytes | None = None,
        key_type: KeyType = KeyType.EC_EDWARDS,
    ) -> bytes:
        """
        Read the raw 32-byte public key for a key on the token.

        :param key_label: PKCS#11 ``CKA_LABEL`` of the public key.
        :param key_id: PKCS#11 ``CKA_ID`` of the public key.
        :param key_type: Key type to look up (default: ``EC_EDWARDS``).
        :returns: Raw 32-byte public key.
        :raises PKCS11KeyNotFoundError: if the key is not found.
        """
        with self._lock:
            def _do_read_pub(session):
                pub = self._find_key(
                    session,
                    ObjectClass.PUBLIC_KEY,
                    key_type,
                    key_label=key_label,
                    key_id=key_id,
                )
                ec_point = pub[Attribute.EC_POINT]
                return _ec_point_to_raw(bytes(ec_point))
            try:
                return self._execute_with_recovery(_do_read_pub)
            except PKCS11BackendError:
                raise
            except Exception as exc:
                raise PKCS11BackendError(f"Could not read public key: {exc}") from exc

    def generate_ed25519_keypair(
        self,
        label: str,
        key_id: bytes | None = None,
        *,
        store: bool = True,
    ):
        """
        Generate an Ed25519 signing keypair on the token.

        This is a convenience helper used in tests and initial setup.
        Returns ``(public_key_object, private_key_object)``.
        """
        with self._lock:
            session = self._require_session()
            try:
                return session.generate_keypair(
                    KeyType.EC_EDWARDS,
                    key_length=None,
                    store=store,
                    mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                    public_template={
                        Attribute.EC_PARAMS: _ED25519_PARAMS,
                        Attribute.VERIFY: True,
                        Attribute.TOKEN: store,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                    private_template={
                        Attribute.SIGN: True,
                        Attribute.TOKEN: store,
                        Attribute.SENSITIVE: True,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                )
            except Exception as exc:
                raise PKCS11BackendError(f"Ed25519 key generation failed: {exc}") from exc

    def generate_x25519_keypair(
        self,
        label: str,
        key_id: bytes | None = None,
        *,
        store: bool = True,
    ):
        """
        Generate an X25519 encryption keypair on the token.

        This is a convenience helper used in tests and initial setup.
        Returns ``(public_key_object, private_key_object)``.
        """
        with self._lock:
            session = self._require_session()
            try:
                return session.generate_keypair(
                    KeyType.EC_EDWARDS,
                    key_length=None,
                    store=store,
                    mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                    public_template={
                        Attribute.EC_PARAMS: _X25519_PARAMS,
                        Attribute.DERIVE: True,
                        Attribute.TOKEN: store,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                    private_template={
                        Attribute.DERIVE: True,
                        Attribute.TOKEN: store,
                        Attribute.SENSITIVE: True,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                )
            except Exception as exc:
                raise PKCS11BackendError(f"X25519 key generation failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self):
        return self._get_token_for_session()

    def _get_token_for_session(self, token_selection_callback=None):
        candidates = self._find_token_candidates()
        if len(candidates) == 0:
            self._state = SessionLifecycle.SESSION_LOST
            if self._token_label:
                raise PKCS11SessionError(
                    f"PKCS#11 token '{self._token_label}' is not present"
                )
            raise PKCS11SessionError("No suitable PKCS#11 token is present")

        if self._bound_token_fingerprint is not None:
            for _, token in candidates:
                if self._token_fingerprint(token) == self._bound_token_fingerprint:
                    return token
            self._state = SessionLifecycle.TOKEN_CHANGED
            raise PKCS11SessionError(
                "A different PKCS#11 token is now present for this runtime. "
                "Refusing automatic switch; rebind explicitly to continue."
            )

        if len(candidates) == 1:
            return candidates[0][1]
        return self._choose_token_candidate(candidates, token_selection_callback)

    def _find_token_candidates(self):
        candidates = []
        try:
            slots = list(self._lib.get_slots(token_present=True))
        except Exception as exc:
            raise PKCS11SessionError(f"Could not enumerate PKCS#11 slots: {exc}") from exc
        for slot in slots:
            if self._slot_id is not None and slot.slot_id != self._slot_id:
                continue
            try:
                token = slot.get_token()
            except pkcs11.exceptions.TokenNotPresent:
                continue
            except Exception:
                continue
            if self._token_label is not None:
                token_label = (getattr(token, "label", "") or "").strip()
                if token_label != self._token_label:
                    continue
            candidates.append((slot.slot_id, token))
        candidates.sort(key=lambda item: item[0])
        return candidates

    def _choose_token_candidate(self, candidates, token_selection_callback=None):
        if token_selection_callback is not None:
            selected_index = token_selection_callback(candidates)
            if 0 <= selected_index < len(candidates):
                return candidates[selected_index][1]
            raise PKCS11SessionError("Invalid PKCS#11 token selection callback result")

        print("Multiple matching PKCS#11 tokens are available:")
        for idx, (slot_id, token) in enumerate(candidates, start=1):
            print(
                f"  [{idx}] slot={slot_id} "
                f"label={getattr(token, 'label', '<unknown>')} "
                f"serial={getattr(token, 'serial', '<unknown>')}"
            )
        while True:
            selection = input("Select PKCS#11 token number: ").strip()
            if selection.isdigit():
                index = int(selection) - 1
                if 0 <= index < len(candidates):
                    return candidates[index][1]
            print("Invalid selection. Please enter a valid token number.")

    @staticmethod
    def _token_fingerprint(token) -> tuple[str, str, int]:
        label = (getattr(token, "label", "") or "").strip()
        serial = (getattr(token, "serial", "") or "").strip()
        slot = int(getattr(token.slot, "slot_id", -1))
        return (label, serial, slot)

    def _bind_or_validate_token_binding(
        self,
        fingerprint: tuple[str, str, int],
        *,
        force_rebind: bool = False,
    ) -> None:
        if self._bound_token_fingerprint is None or force_rebind:
            self._bound_token_fingerprint = fingerprint
            return
        if self._bound_token_fingerprint != fingerprint:
            self._state = SessionLifecycle.TOKEN_CHANGED
            raise PKCS11SessionError(
                "Inserted PKCS#11 token does not match the runtime-bound token"
            )

    def _require_session(self) -> pkcs11.Session:
        """Return the current session, raising if it is not open."""
        if self._session is None:
            raise PKCS11SessionError(
                "PKCS#11 session is not open; call open_session() first"
            )
        return self._session

    def _is_session_failure(self, exc: Exception) -> bool:
        return isinstance(
            exc,
            (
                pkcs11.exceptions.TokenNotPresent,
                pkcs11.exceptions.DeviceRemoved,
                pkcs11.exceptions.SessionClosed,
                pkcs11.exceptions.SessionHandleInvalid,
                PKCS11SessionError,
            ),
        )

    def _mark_session_lost(self, exc: Exception | None = None) -> None:
        self._state = SessionLifecycle.SESSION_LOST
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    def _reopen_session(self) -> None:
        self.open_session(
            pin=self._pin,
            pin_callback=self._pin_callback,
            prompt=self._prompt,
        )

    def rebind_to_current_token(
        self,
        *,
        pin: str | None = None,
        pin_callback=None,
        prompt: str | None = None,
        token_selection_callback=None,
    ) -> None:
        with self._lock:
            self.close()
            self.open_session(
                pin=pin if pin is not None else self._pin,
                pin_callback=pin_callback if pin_callback is not None else self._pin_callback,
                prompt=prompt if prompt is not None else self._prompt,
                token_selection_callback=token_selection_callback,
                force_rebind=True,
            )

    def _execute_with_recovery(self, operation):
        session = self._require_session()
        try:
            return operation(session)
        except Exception as exc:
            if not self._is_session_failure(exc):
                raise
            self._mark_session_lost(exc)
            self._reopen_session()
            session = self._require_session()
            return operation(session)

    def _find_key(
        self,
        session: pkcs11.Session,
        object_class: ObjectClass,
        key_type: KeyType,
        *,
        key_label: str | None,
        key_id: bytes | None,
    ):
        """Look up a key object on the token by label and/or id."""
        kwargs = {"object_class": object_class, "key_type": key_type}
        if key_label is not None:
            kwargs["label"] = key_label
        if key_id is not None:
            kwargs["id"] = key_id
        try:
            return session.get_key(**kwargs)
        except pkcs11.exceptions.NoSuchKey as exc:
            identifier = key_label or (key_id.hex() if key_id else "<unspecified>")
            raise PKCS11KeyNotFoundError(
                f"Key '{identifier}' ({object_class.name}/{key_type.name}) not found on token"
            ) from exc
        except pkcs11.exceptions.MultipleObjectsReturned as exc:
            identifier = key_label or (key_id.hex() if key_id else "<unspecified>")
            raise PKCS11BackendError(
                f"Multiple keys named '{identifier}' found; use a unique label or key_id"
            ) from exc

    @staticmethod
    def _resolve_pin(
        pin: str | None,
        pin_callback,
        prompt: str | None,
    ) -> str:
        if pin is not None:
            return pin
        if pin_callback is not None:
            return pin_callback()
        return getpass.getpass(prompt or "PKCS#11 user PIN: ")
