"""
PKCS#11 PIV backend for multi-app hardware identities.

This module provides low-level PKCS#11 session management for PIV tokens
(YubiKey). It handles session lifecycle, key operations (sign/ECDH), and
transparent recovery on token removal/reinsertion.

Design:
  - PIV-aware: understands slots 9a, 9c, 9d, 9e
  - App-agnostic: works with any application
  - Thread-safe: serializes operations with lock
  - Recoverable: transparent session reopening on token loss
"""

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
    SlotNotFoundError,
)

# DER-encoded OID prefixes for Edwards curves
# Ed25519 OID 1.3.101.112 → 06 03 2B 65 70
_ED25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
# X25519 OID 1.3.101.110 → 06 03 2B 65 6E
_X25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])

# DER EC_POINT prefix for 32-byte keys: 04 20
_EC_POINT_PREFIX = bytes([0x04, 0x20])

# PIV slot identifiers
PIV_SLOTS = {
    "9a": "AUTHENTICATION",
    "9c": "SIGNATURE",
    "9d": "KEY_MANAGEMENT",
    "9e": "CARD_AUTHENTICATION",
}


class SessionLifecycle(str, Enum):
    """Session state machine."""
    NO_SESSION = "no_session"
    ACTIVE_SESSION = "active_session"
    SESSION_LOST = "session_lost"
    TOKEN_CHANGED = "token_changed"


class PIVSlot(str, Enum):
    """PIV slot identifiers."""
    AUTHENTICATION = "9a"
    SIGNATURE = "9c"
    KEY_MANAGEMENT = "9d"
    CARD_AUTHENTICATION = "9e"


def _ec_point_to_raw(ec_point: bytes) -> bytes:
    """Strip DER EC_POINT prefix to get raw 32-byte key."""
    if len(ec_point) != 34 or ec_point[:2] != _EC_POINT_PREFIX:
        raise PKCS11BackendError(
            f"Invalid EC_POINT format (expected 34 bytes with 04 20 prefix, got {len(ec_point)}): {ec_point.hex()}"
        )
    return ec_point[2:]


def _raw_to_ec_point(raw: bytes) -> bytes:
    """Prepend DER EC_POINT prefix to raw 32-byte key."""
    if len(raw) != 32:
        raise PKCS11BackendError(
            f"Expected 32-byte raw key for EC_POINT, got {len(raw)} bytes"
        )
    return _EC_POINT_PREFIX + raw


class PKCS11PIVBackend:
    """
    Low-level PKCS#11 interface for PIV tokens (YubiKey).

    Manages session lifecycle, provides sign/ECDH operations, handles
    token removal/reinsertion transparently.
    """

    def __init__(
        self,
        module_path: str,
        slot_id: int | None = None,
        token_label: str | None = None,
    ):
        """
        Initialize backend for a PIV token.

        Args:
            module_path: Path to PKCS#11 module (libykcs11.dll, opensc-pkcs11.so)
            slot_id: Specific slot ID to use
            token_label: Specific token label to search for
        """
        if slot_id is None and token_label is None:
            raise PKCS11BackendError("Either slot_id or token_label must be specified")

        try:
            self._lib = pkcs11.lib(module_path)
        except Exception as exc:
            raise PKCS11BackendError(f"Failed to load PKCS#11 module: {exc}") from exc

        self._module_path = module_path
        self._slot_id = slot_id
        self._token_label = token_label
        self._session = None
        self._lock = threading.RLock()
        self._state = SessionLifecycle.NO_SESSION
        self._pin = None
        self._bound_token = None

    @property
    def lifecycle(self) -> SessionLifecycle:
        """Current session lifecycle state."""
        return self._state

    def open_session(self, pin: str | None = None) -> None:
        """
        Open PKCS#11 session and authenticate.

        Args:
            pin: PIN for token (default: 123456 for YubiKey)
        """
        with self._lock:
            if self._state == SessionLifecycle.ACTIVE_SESSION:
                return

            self._pin = pin or "123456"

            try:
                token = self._find_token()
                self._bound_token = (token.label, token.serial, self._slot_id)

                # python-pkcs11 authenticates at session-open time via the
                # ``user_pin`` argument; there is no separate ``Session.login()``
                # method. Surfacing PinLocked/PinIncorrect distinctly is important
                # for hardware safety: callers must NOT retry on a wrong PIN, as
                # repeated failures lock the token's PIN counter.
                try:
                    self._session = token.open(rw=True, user_pin=self._pin)
                except pkcs11.exceptions.PinLocked as exc:
                    raise PKCS11LoginError(
                        "PIN is locked; the token's PIV applet must be reset"
                    ) from exc
                except pkcs11.exceptions.PinIncorrect as exc:
                    raise PKCS11LoginError("Incorrect PIN") from exc
                except Exception as exc:
                    raise PKCS11LoginError(f"Failed to authenticate: {exc}") from exc

                self._state = SessionLifecycle.ACTIVE_SESSION
            except Exception as exc:
                self._state = SessionLifecycle.SESSION_LOST
                raise

    def close(self) -> None:
        """Close session and logout."""
        with self._lock:
            if self._session:
                try:
                    self._session.logout()
                except:
                    pass
                try:
                    self._session.close()
                except:
                    pass
                self._session = None
            self._state = SessionLifecycle.NO_SESSION

    def _find_token(self) -> pkcs11.Token:
        """Find and return the target token."""
        try:
            slots = list(self._lib.get_slots(token_present=True))
        except Exception as exc:
            raise PKCS11SessionError(f"Failed to enumerate slots: {exc}") from exc

        for slot in slots:
            if self._slot_id is not None and slot.slot_id != self._slot_id:
                continue

            try:
                token = slot.get_token()
            except:
                continue

            if self._token_label is not None:
                token_label = (getattr(token, "label", "") or "").strip()
                if token_label != self._token_label:
                    continue

            return token

        raise SlotNotFoundError(
            f"No token found (slot_id={self._slot_id}, label={self._token_label})"
        )

    def _require_session(self) -> pkcs11.Session:
        """Ensure session is open, with recovery on loss."""
        with self._lock:
            if self._state == SessionLifecycle.SESSION_LOST:
                self.open_session(self._pin)
            if self._session is None:
                raise PKCS11SessionError("No active session")
            return self._session

    def sign(self, message: bytes, key_label: str | None = None) -> bytes:
        """
        Sign a message using Ed25519 key.

        Args:
            message: Message to sign
            key_label: Key label to use (app-specific)

        Returns:
            Raw signature bytes
        """
        with self._lock:
            session = self._require_session()

            try:
                # Find Ed25519 private key by label
                keys = list(
                    session.get_objects({
                        ObjectClass.PRIVATE_KEY: None,
                        KeyType.EC_EDWARDS: None,
                        Attribute.LABEL: key_label,
                    })
                )

                if not keys:
                    raise PKCS11KeyNotFoundError(
                        f"Ed25519 key not found: {key_label}"
                    )

                key = keys[0]

                # Sign with EDDSA mechanism
                return session.sign(
                    key,
                    message,
                    mechanism=Mechanism.EDDSA,
                )
            except PKCS11KeyNotFoundError:
                raise
            except Exception as exc:
                raise PKCS11BackendError(f"Sign operation failed: {exc}") from exc

    def get_public_key(self, key_label: str | None = None) -> bytes:
        """
        Get raw 32-byte public key (Ed25519 or X25519).

        Args:
            key_label: Key label to retrieve

        Returns:
            Raw 32-byte public key
        """
        with self._lock:
            session = self._require_session()

            try:
                keys = list(
                    session.get_objects({
                        ObjectClass.PUBLIC_KEY: None,
                        Attribute.LABEL: key_label,
                    })
                )

                if not keys:
                    raise PKCS11KeyNotFoundError(f"Public key not found: {key_label}")

                pub_key = keys[0]
                ec_point = pub_key[Attribute.EC_POINT]
                return _ec_point_to_raw(bytes(ec_point))
            except PKCS11KeyNotFoundError:
                raise
            except Exception as exc:
                raise PKCS11BackendError(f"Key retrieval failed: {exc}") from exc

    def generate_ed25519_keypair(
        self,
        label: str,
        key_id: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Generate Ed25519 keypair on token (stores private key).

        Args:
            label: Key label
            key_id: Optional key ID

        Returns:
            (public_key_raw, private_key_raw) - but private stays on token
        """
        with self._lock:
            session = self._require_session()

            try:
                pub, priv = session.generate_keypair(
                    KeyType.EC_EDWARDS,
                    mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                    public_template={
                        Attribute.EC_PARAMS: _ED25519_OID,
                        Attribute.VERIFY: True,
                        Attribute.TOKEN: True,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                    private_template={
                        Attribute.SIGN: True,
                        Attribute.TOKEN: True,
                        Attribute.SENSITIVE: True,
                        Attribute.EXTRACTABLE: False,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                )

                pub_bytes = _ec_point_to_raw(bytes(pub[Attribute.EC_POINT]))
                return (pub_bytes, None)  # Private stays on token
            except Exception as exc:
                raise PKCS11BackendError(f"Ed25519 key generation failed: {exc}") from exc

    def generate_x25519_keypair(
        self,
        label: str,
        key_id: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Generate X25519 keypair on token (stores private key).

        Args:
            label: Key label
            key_id: Optional key ID

        Returns:
            (public_key_raw, private_key_raw) - but private stays on token
        """
        with self._lock:
            session = self._require_session()

            try:
                pub, priv = session.generate_keypair(
                    KeyType.EC_EDWARDS,
                    mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                    public_template={
                        Attribute.EC_PARAMS: _X25519_OID,
                        Attribute.DERIVE: True,
                        Attribute.TOKEN: True,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                    private_template={
                        Attribute.DERIVE: True,
                        Attribute.TOKEN: True,
                        Attribute.SENSITIVE: True,
                        Attribute.EXTRACTABLE: False,
                        Attribute.LABEL: label,
                        Attribute.ID: key_id or label.encode(),
                    },
                )

                pub_bytes = _ec_point_to_raw(bytes(pub[Attribute.EC_POINT]))
                return (pub_bytes, None)  # Private stays on token
            except Exception as exc:
                raise PKCS11BackendError(f"X25519 key generation failed: {exc}") from exc

    def ecdh_derive(
        self,
        key_label: str,
        peer_public_key: bytes,
    ) -> bytes:
        """
        Perform ECDH derivation using X25519 key.

        Args:
            key_label: Label of X25519 key on token
            peer_public_key: Peer's 32-byte public key

        Returns:
            Shared secret (32 bytes)
        """
        with self._lock:
            session = self._require_session()

            try:
                # Find X25519 private key
                keys = list(
                    session.get_objects({
                        ObjectClass.PRIVATE_KEY: None,
                        Attribute.LABEL: key_label,
                    })
                )

                if not keys:
                    raise PKCS11KeyNotFoundError(f"ECDH key not found: {key_label}")

                priv_key = keys[0]

                # Perform ECDH derivation
                peer_ec_point = _raw_to_ec_point(peer_public_key)

                derived = session.derive_key(
                    priv_key,
                    Mechanism(
                        "ecdh1-derive",
                        {
                            "kdf": KDF.SHA256,
                            "publicData": peer_ec_point,
                        },
                    ),
                    key_type=KeyType.AES,
                    class_=ObjectClass.SECRET_KEY,
                    extractable=True,
                )

                # Extract derived key
                derived_bytes = derived[Attribute.VALUE]
                return bytes(derived_bytes)
            except PKCS11KeyNotFoundError:
                raise
            except Exception as exc:
                raise PKCS11BackendError(f"ECDH derivation failed: {exc}") from exc

    def ensure_keys_for_app(
        self,
        app_name: str,
        slot: str | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Ensure Ed25519 and X25519 keys exist for a multi-app identity.

        Checks if keys exist for the app. If either key is missing, generates it
        on the token. Keys are labeled with app name for per-app isolation.

        Args:
            app_name: Application identifier for key labeling
            slot: PIV slot hint (e.g., "9a" for AUTHENTICATION) - informational only

        Returns:
            (ed25519_public_key_raw, x25519_public_key_raw) tuple

        Raises:
            PKCS11BackendError: If key generation fails
            PKCS11KeyNotFoundError: If keys cannot be retrieved after generation

        Notes:
            - Ed25519 key labeled as "{app_name}-sign"
            - X25519 key labeled as "{app_name}-enc"
            - Keys are generated on-device (never leave token)
            - All keys set CKA_EXTRACTABLE = False
            - Subsequent calls return existing keys
            - Thread-safe: operations serialized with lock
        """
        with self._lock:
            session = self._require_session()
            ed_label = f"{app_name}-sign"
            x_label = f"{app_name}-enc"

            try:
                # Check for existing Ed25519 key
                ed_keys = list(
                    session.get_objects({
                        ObjectClass.PRIVATE_KEY: None,
                        KeyType.EC_EDWARDS: None,
                        Attribute.LABEL: ed_label,
                    })
                )

                if not ed_keys:
                    # Generate Ed25519 keypair
                    session.generate_keypair(
                        KeyType.EC_EDWARDS,
                        mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                        public_template={
                            Attribute.EC_PARAMS: _ED25519_OID,
                            Attribute.VERIFY: True,
                            Attribute.TOKEN: True,
                            Attribute.LABEL: ed_label,
                            Attribute.ID: ed_label.encode(),
                        },
                        private_template={
                            Attribute.SIGN: True,
                            Attribute.TOKEN: True,
                            Attribute.SENSITIVE: True,
                            Attribute.EXTRACTABLE: False,
                            Attribute.PRIVATE: True,
                            Attribute.LABEL: ed_label,
                            Attribute.ID: ed_label.encode(),
                        },
                    )

                # Check for existing X25519 key
                x_keys = list(
                    session.get_objects({
                        ObjectClass.PRIVATE_KEY: None,
                        KeyType.EC_EDWARDS: None,
                        Attribute.LABEL: x_label,
                    })
                )

                if not x_keys:
                    # Generate X25519 keypair
                    session.generate_keypair(
                        KeyType.EC_EDWARDS,
                        mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                        public_template={
                            Attribute.EC_PARAMS: _X25519_OID,
                            Attribute.DERIVE: True,
                            Attribute.TOKEN: True,
                            Attribute.LABEL: x_label,
                            Attribute.ID: x_label.encode(),
                        },
                        private_template={
                            Attribute.DERIVE: True,
                            Attribute.TOKEN: True,
                            Attribute.SENSITIVE: True,
                            Attribute.EXTRACTABLE: False,
                            Attribute.PRIVATE: True,
                            Attribute.LABEL: x_label,
                            Attribute.ID: x_label.encode(),
                        },
                    )

                # Retrieve public keys - query directly within lock to avoid re-entrance
                ed_pub_keys = list(
                    session.get_objects({
                        ObjectClass.PUBLIC_KEY: None,
                        Attribute.LABEL: ed_label,
                    })
                )
                if not ed_pub_keys:
                    raise PKCS11KeyNotFoundError(f"Public key not found after generation: {ed_label}")
                ed_pub_bytes = _ec_point_to_raw(bytes(ed_pub_keys[0][Attribute.EC_POINT]))

                x_pub_keys = list(
                    session.get_objects({
                        ObjectClass.PUBLIC_KEY: None,
                        Attribute.LABEL: x_label,
                    })
                )
                if not x_pub_keys:
                    raise PKCS11KeyNotFoundError(f"Public key not found after generation: {x_label}")
                x_pub_bytes = _ec_point_to_raw(bytes(x_pub_keys[0][Attribute.EC_POINT]))

                return (ed_pub_bytes, x_pub_bytes)

            except PKCS11KeyNotFoundError:
                raise
            except Exception as exc:
                raise PKCS11BackendError(
                    f"Failed to ensure keys for app '{app_name}': {exc}"
                ) from exc
