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

"""Multi-app hardware identity factory for Reticulum.

This module provides hardware-backed identity creation for RNS.Identity,
supporting both LXMF-specific identities (backward compat) and multi-app
identities via PIV slots on PKCS#11 tokens like YubiKey.

Key functions:
  - make_lxmf_identity_class(): Original factory (backward compat)
  - make_app_hardware_identity_class(): Multi-app factory
  - create_app_hardware_identity(): Convenience utility
  - get_app_identity_keys(): Query keys for an app
"""

import os
from typing import Optional

import RNS
from RNS.Cryptography import (
    Ed25519PublicKey,
    X25519PrivateKey,
    X25519PublicKey,
)
from RNS.Cryptography import Token
from RNS.Identity import Identity as _OriginalIdentity

from .backend import PKCS11Backend, raw_to_ec_point
from .exceptions import PKCS11BackendError, PKCS11KeyNotFoundError

# Public-key size constants mirrored from RNS.Identity.
_HALF_KEYSIZE = _OriginalIdentity.KEYSIZE // 8 // 2  # 32 bytes


class _TokenSigningKeyAdapter:
    """Private-key stand-in for an Ed25519 key whose secret lives on a token.

    When a destination accepts an inbound link, RNS reads
    ``identity.sig_prv`` **directly** (``RNS.Link.__init__`` responder branch):
    it calls ``sig_prv.public_key()`` to derive the link's signing public key
    and later ``sig_prv.sign(...)`` to prove link packets. A hardware identity
    holds no in-process private key (``sig_prv`` would be ``None``), so without
    this adapter RNS raises ``'NoneType' object has no attribute 'public_key'``
    and the destination cannot act as a link responder.

    The adapter exposes the real public key and routes signing back through the
    owning identity (and therefore the PKCS#11 token).
    """

    __slots__ = ("_identity",)

    def __init__(self, identity):
        self._identity = identity

    def public_key(self):
        return self._identity.sig_pub

    def sign(self, message: bytes) -> bytes:
        return self._identity.sign(message)


class _TokenResidentPrivateKey:
    """Truthy placeholder for an X25519 private key that lives on the token.

    RNS gates delivery-proof generation on ``identity.prv`` being truthy
    (``RNS.Packet.prove``), yet ``Identity.prove`` produces the proof through
    ``identity.sign()`` — which a hardware identity already routes to the
    token. A hardware identity holds no in-process encryption key, so without
    this marker ``prv`` is ``None`` and the radio can never prove receipt of a
    packet, breaking opportunistic delivery proofs and ``PROVE_ALL`` endpoints.

    The marker is only ever read for its truthiness: the actual X25519 ECDH is
    performed on the token inside ``decrypt()``. ``prv_bytes`` deliberately
    stays ``None`` so the identity still reports that it holds no in-memory
    private key.
    """

    __slots__ = ()

    def __bool__(self):
        return True

    def __repr__(self):
        return "<token-resident X25519 private key>"


_TOKEN_RESIDENT_PRV = _TokenResidentPrivateKey()


def make_lxmf_identity_class(
    backend: PKCS11Backend,
    sign_key_label: str,
    enc_key_label: str,
    sign_key_id: bytes | None = None,
    enc_key_id: bytes | None = None,
) -> type:
    """
    Factory that produces a *HardwareIdentity* class pre-bound to *backend*.

    This is the correct way to instantiate HardwareIdentity — call this factory
    once during application setup and use the returned class for your explicit
    LXMF user identity object.

    :param backend: An already-opened :class:`~.backend.PKCS11Backend`.
    :param sign_key_label: PKCS#11 label of the Ed25519 signing private key.
    :param enc_key_label: PKCS#11 label of the X25519 encryption private key.
    :param sign_key_id: Optional PKCS#11 ``CKA_ID`` for the signing key.
    :param enc_key_id: Optional PKCS#11 ``CKA_ID`` for the encryption key.
    :returns: A new class derived from ``RNS.Identity``.
    """

    class HardwareIdentity(_OriginalIdentity):
        """
        A Reticulum Identity backed by a PKCS#11 token.

        Private-key operations (signing and ECDH decryption) are performed
        inside the hardware token.  Public-key operations (encryption,
        signature verification, hashing) happen in software, exactly as
        the stock ``RNS.Identity`` does.

        The token PIN is prompted **once** when the backend session is
        opened.  It is never requested again during normal operation.
        """

        # Class-level references shared by all "local" (hardware-backed)
        # instances of this class.
        _backend: PKCS11Backend = backend
        _sign_key_label: str = sign_key_label
        _sign_key_id: bytes | None = sign_key_id
        _enc_key_label: str = enc_key_label
        _enc_key_id: bytes | None = enc_key_id

        def __init__(self, create_keys: bool = True):
            # Skip the parent __init__ entirely: we never want to generate
            # random software keys.  We set the same instance attributes
            # manually so the rest of Reticulum can use us normally.
            self.prv           = None
            self.prv_bytes     = None
            self.sig_prv       = None
            self.sig_prv_bytes = None

            self.pub           = None
            self.pub_bytes     = None
            self.sig_pub       = None
            self.sig_pub_bytes = None

            self.hash          = None
            self.hexhash       = None

            # Marks this instance as the hardware-backed local identity.
            self._is_local_hardware = False

            if create_keys:
                self._load_keys_from_token()

        # ------------------------------------------------------------------
        # Key loading
        # ------------------------------------------------------------------

        def _load_keys_from_token(self):
            """Load public keys from the token and mark this as a local identity."""
            try:
                enc_pub_raw = self._backend.get_public_key_bytes(
                    key_label=self._enc_key_label,
                    key_id=self._enc_key_id,
                )
                sign_pub_raw = self._backend.get_public_key_bytes(
                    key_label=self._sign_key_label,
                    key_id=self._sign_key_id,
                )
            except PKCS11KeyNotFoundError as exc:
                raise PKCS11KeyNotFoundError(
                    "Identity key not found on token — generate the required key pairs on the token (see README): "
                    f"{exc}"
                ) from exc

            self.pub_bytes     = enc_pub_raw
            self.sig_pub_bytes = sign_pub_raw

            self.pub     = X25519PublicKey.from_public_bytes(self.pub_bytes)
            self.sig_pub = Ed25519PublicKey.from_public_bytes(self.sig_pub_bytes)

            self.update_hashes()
            self._is_local_hardware = True

            # Let RNS use this identity as a *link responder*. The responder
            # path in RNS reads ``identity.sig_prv`` directly (it does not call
            # ``sign()``), so expose an adapter that yields the real public key
            # and routes signing to the token. ``prv`` stays a token-resident
            # marker (see below): link encryption uses freshly generated
            # ephemeral X25519 keys, never the identity's static encryption key.
            self.sig_prv = _TokenSigningKeyAdapter(self)

            # RNS only generates delivery proofs when ``identity.prv`` is truthy
            # (``RNS.Packet.prove``); the proof itself is produced via
            # ``sign()`` on the token. Expose a truthy marker so this radio can
            # prove packet receipt. ``prv_bytes`` stays ``None`` — we still hold
            # no in-memory private key.
            self.prv = _TOKEN_RESIDENT_PRV

            RNS.log(
                f"Hardware identity loaded from PKCS#11 token "
                f"(hash {RNS.prettyhexrep(self.hash)})",
                RNS.LOG_VERBOSE,
            )

        def _check_token_state(self):
            """
            Check for token changes and raise if detected.

            This is called before each cryptographic operation to detect
            if the token has been swapped. If a change is detected, the
            session is invalidated and a clear error is raised.

            :raises RuntimeError: If token state has changed
            """
            try:
                monitor = self._backend.get_token_monitor()
                changed, reason = monitor.detect_changes()
                if changed:
                    monitor.invalidate_sessions()
                    raise RuntimeError(
                        f"PKCS#11 token has changed: {reason}. "
                        "Please re-authenticate with PIN or physical card."
                    )
            except RuntimeError:
                raise
            except Exception as exc:
                RNS.log(
                    f"Token state check failed: {exc}",
                    RNS.LOG_DEBUG,
                ) if RNS.sl(RNS.LOG_DEBUG) else None

        # ------------------------------------------------------------------
        # Static / class-method overrides
        # ------------------------------------------------------------------

        @staticmethod
        def from_file(path: str) -> "HardwareIdentity | None":
            """
            Load a Reticulum identity.

            This method always loads the public keys from the token, ignoring
            private-key content of any saved identity file. If a public key is
            already saved at *path*, its hash is compared to the token's key to
            warn about mismatches.
            """
            identity = HardwareIdentity(create_keys=False)
            identity._load_keys_from_token()

            # If a saved identity file exists, verify it matches the token.
            if os.path.isfile(path):
                try:
                    with open(path, "rb") as fh:
                        saved_bytes = fh.read()
                    # The file may contain a full private key (64 bytes) or
                    # just a public key (64 bytes — same length after the
                    # KEYSIZE//8 split used in load_public_key).
                    # We only care about verifying that the public portion
                    # matches what the token presents.
                    pub_candidate = saved_bytes[: _OriginalIdentity.KEYSIZE // 8]
                    if len(pub_candidate) == _OriginalIdentity.KEYSIZE // 8:
                        saved_pub_hash = _OriginalIdentity.truncated_hash(pub_candidate)
                        if saved_pub_hash != identity.hash:
                            RNS.log(
                                "Saved identity does not match the PKCS#11 token. "
                                "The token's identity will be used. "
                                f"(saved: {saved_pub_hash.hex()}, token: {identity.hash.hex()})",
                                RNS.LOG_WARNING,
                            )
                except Exception as exc:
                    RNS.log(
                        f"Could not read saved identity at '{path}': {exc}",
                        RNS.LOG_WARNING,
                    )

            return identity

        @staticmethod
        def from_bytes(prv_bytes: bytes) -> "HardwareIdentity | None":
            """
            Create a public-key-only identity from raw bytes.

            This is used internally by Reticulum for interface access control
            and does not touch the PKCS#11 token.
            """
            identity = HardwareIdentity(create_keys=False)
            identity.load_public_key(prv_bytes[: _OriginalIdentity.KEYSIZE // 8])
            return identity

        # ------------------------------------------------------------------
        # Key persistence
        # ------------------------------------------------------------------

        def to_file(self, path: str) -> bool:
            """
            Persist the identity to *path*.

            Only the **public** key is written; the private key always stays in
            the token and is never written to disk.
            """
            return self.pub_to_file(path)

        def get_private_key(self):
            """
            Return the private key bytes.

            For hardware identities the private key never leaves the PKCS#11
            token, so this method returns the public key bytes as a stable,
            unique identifier.  This allows Reticulum to derive its internal
            RPC key without exposing any secret material.
            """
            if self._is_local_hardware:
                return self.get_public_key()
            return super().get_private_key()

        # ------------------------------------------------------------------
        # Signing — delegated to the token
        # ------------------------------------------------------------------

        def sign(self, message: bytes) -> bytes:
            """
            Sign *message* using the Ed25519 key on the PKCS#11 token.

            For remote identities that carry only a public key this raises
            ``KeyError``, identical to the stock ``RNS.Identity`` behaviour.
            """
            if self._is_local_hardware:
                try:
                    self._check_token_state()
                    return self._backend.sign(
                        message,
                        key_label=self._sign_key_label,
                        key_id=self._sign_key_id,
                    )
                except Exception as exc:
                    raise RuntimeError(
                        f"PKCS#11 signing failed: {exc}"
                    ) from exc
            # Fall back to software signing for non-hardware instances
            # (e.g. a software identity loaded explicitly for testing).
            if self.sig_prv is not None:
                return self.sig_prv.sign(message)
            raise KeyError("Signing failed because identity does not hold a private key")

        # ------------------------------------------------------------------
        # Decryption — ECDH in token, HKDF + AES in software
        # ------------------------------------------------------------------

        def decrypt(
            self,
            ciphertext_token: bytes,
            ratchets=None,
            enforce_ratchets: bool = False,
            ratchet_id_receiver=None,
        ):
            """
            Decrypt a Reticulum ciphertext token.

            The X25519 ECDH operation is performed inside the PKCS#11 token so
            the private key never leaves the hardware.  HKDF key derivation and
            AES decryption are performed in software using the extracted shared
            secret, exactly as the stock ``RNS.Identity.decrypt`` does.

            Ratchet-based decryption (using ephemeral software ratchet keys) is
            handled identically to the stock implementation because ratchet
            private keys are ordinary in-memory keys.

            For remote identities that carry only a public key this raises
            ``KeyError``.
            """
            if not self._is_local_hardware:
                # Delegate to stock implementation; it will raise KeyError if
                # no private key is available, which is the expected behaviour.
                return super().decrypt(
                    ciphertext_token,
                    ratchets=ratchets,
                    enforce_ratchets=enforce_ratchets,
                    ratchet_id_receiver=ratchet_id_receiver,
                )

            # Check for token changes before attempting ECDH operation
            self._check_token_state()

            if len(ciphertext_token) <= _HALF_KEYSIZE:
                RNS.log(
                    "Decryption failed because the token size was invalid.",
                    RNS.LOG_DEBUG,
                ) if RNS.sl(RNS.LOG_DEBUG) else None
                return None

            plaintext = None

            try:
                peer_pub_bytes = ciphertext_token[:_HALF_KEYSIZE]
                ciphertext     = ciphertext_token[_HALF_KEYSIZE:]

                # ---------------------------------------------------------
                # 1. Try ratchet keys (in-memory software keys, same as stock)
                # ---------------------------------------------------------
                if ratchets:
                    for ratchet in ratchets:
                        try:
                            ratchet_prv = X25519PrivateKey.from_private_bytes(ratchet)
                            ratchet_id = _OriginalIdentity._get_ratchet_id(
                                ratchet_prv.public_key().public_bytes()
                            )
                            peer_pub    = X25519PublicKey.from_public_bytes(peer_pub_bytes)
                            shared_key  = ratchet_prv.exchange(peer_pub)
                            plaintext   = self._hw_finish_decrypt(shared_key, ciphertext)
                            if ratchet_id_receiver is not None:
                                ratchet_id_receiver.latest_ratchet_id = ratchet_id
                            break
                        except Exception:
                            pass

                if enforce_ratchets and plaintext is None:
                    RNS.log(
                        f"Decryption with ratchet enforcement by "
                        f"{RNS.prettyhexrep(self.hash)} failed. Dropping packet.",
                        RNS.LOG_DEBUG,
                    ) if RNS.sl(RNS.LOG_DEBUG) else None
                    if ratchet_id_receiver is not None:
                        ratchet_id_receiver.latest_ratchet_id = None
                    return None

                # ---------------------------------------------------------
                # 2. Main path: ECDH inside the token
                # ---------------------------------------------------------
                if plaintext is None:
                    shared_key = self._backend.ecdh_derive(
                        raw_to_ec_point(peer_pub_bytes),
                        key_label=self._enc_key_label,
                        key_id=self._enc_key_id,
                    )
                    plaintext = self._hw_finish_decrypt(shared_key, ciphertext)
                    if ratchet_id_receiver is not None:
                        ratchet_id_receiver.latest_ratchet_id = None

            except Exception as exc:
                RNS.log(
                    f"Decryption by {RNS.prettyhexrep(self.hash)} failed: {exc}",
                    RNS.LOG_DEBUG,
                ) if RNS.sl(RNS.LOG_DEBUG) else None
                if ratchet_id_receiver is not None:
                    ratchet_id_receiver.latest_ratchet_id = None

            return plaintext

        def _hw_finish_decrypt(self, shared_key: bytes, ciphertext: bytes):
            """HKDF key derivation + AES decryption (identical to stock)."""
            derived_key = RNS.Cryptography.hkdf(
                length=_OriginalIdentity.DERIVED_KEY_LENGTH,
                derive_from=shared_key,
                salt=self.get_salt(),
                context=self.get_context(),
            )
            token = Token(derived_key)
            return token.decrypt(ciphertext)

        # ------------------------------------------------------------------
        # Repr
        # ------------------------------------------------------------------

        def __repr__(self):
            backing = "hardware" if self._is_local_hardware else "public-key-only"
            return (
                f"<HardwareIdentity [{backing}] "
                f"hash={self.hexhash or 'unknown'}>"
            )

    HardwareIdentity.__name__ = "LXMFIdentity"
    HardwareIdentity.__qualname__ = "LXMFIdentity"
    return HardwareIdentity


def make_hardware_identity_class(
    backend: PKCS11Backend,
    sign_key_label: str,
    enc_key_label: str,
    sign_key_id: bytes | None = None,
    enc_key_id: bytes | None = None,
) -> type:
    """Backward-compatible alias for :func:`make_lxmf_identity_class`."""
    return make_lxmf_identity_class(
        backend=backend,
        sign_key_label=sign_key_label,
        enc_key_label=enc_key_label,
        sign_key_id=sign_key_id,
        enc_key_id=enc_key_id,
    )


def make_app_hardware_identity_class(
    app_name: str,
    backend: Optional[PKCS11Backend] = None,
    slot: Optional[str] = None,
) -> type:
    """
    Factory that produces a *HardwareIdentity* class for multi-app use.

    This factory creates a hardware-backed identity class suitable for
    multiple applications, each using its own PIV slot on a PKCS#11 token.

    If backend is None, must be provided explicitly.
    If slot is None, attempts to look it up via AppIdentityMapper.

    :param app_name: Application name (used for slot lookup and logging).
    :param backend: A :class:`~.backend.PKCS11Backend` instance (required).
    :param slot: PIV slot ID ("9a", "9c", "9d", "9e"), or None to auto-lookup.
    :returns: A new class derived from ``RNS.Identity``.
    :raises: PKCS11BackendError if backend/slot cannot be determined or keys not found.
    """

    # Backend must be provided explicitly
    if backend is None:
        raise PKCS11BackendError(
            f"Backend must be provided explicitly for app '{app_name}'"
        )

    # Auto-lookup slot via AppIdentityMapper if needed
    if slot is None:
        try:
            from .app_identity import AppIdentityMapper
            mapper = AppIdentityMapper()
            slot = mapper.get_app_slot(app_name)
            if slot is None:
                raise PKCS11BackendError(
                    f"No PIV slot mapped for app '{app_name}'; use AppIdentityMapper.allocate_slot_for_app()"
                )
        except ImportError:
            raise PKCS11BackendError(
                "app_identity module not available; provide slot explicitly"
            )

    # Determine key labels based on slot (follows PIV convention)
    # Each app's keys are labeled with app_name for clarity
    sign_key_label = f"{app_name}-sign"
    enc_key_label = f"{app_name}-enc"

    class HardwareIdentity(_OriginalIdentity):
        """
        A Reticulum Identity backed by a PKCS#11 token, for multi-app use.

        Private-key operations (signing and ECDH decryption) are performed
        inside the hardware token.  Public-key operations (encryption,
        signature verification, hashing) happen in software, exactly as
        the stock ``RNS.Identity`` does.

        The token PIN is managed by the session manager — no re-prompts
        during app lifetime.
        """

        # Class-level references shared by all instances of this identity class.
        _backend: PKCS11Backend = backend
        _app_name: str = app_name
        _slot: str = slot
        _sign_key_label: str = sign_key_label
        _enc_key_label: str = enc_key_label

        def __init__(self, create_keys: bool = True):
            # Skip the parent __init__ entirely: we never want to generate
            # random software keys.  We set the same instance attributes
            # manually so the rest of Reticulum can use us normally.
            self.prv           = None
            self.prv_bytes     = None
            self.sig_prv       = None
            self.sig_prv_bytes = None

            self.pub           = None
            self.pub_bytes     = None
            self.sig_pub       = None
            self.sig_pub_bytes = None

            self.hash          = None
            self.hexhash       = None

            # Mark as hardware-backed local identity
            self._is_local_hardware = False
            self._app_name_instance = app_name

            if create_keys:
                self._load_keys_from_token()

        # ------------------------------------------------------------------
        # Key loading
        # ------------------------------------------------------------------

        def _load_keys_from_token(self):
            """Load public keys from the token and mark this as a local identity."""
            try:
                enc_pub_raw = self._backend.get_public_key_bytes(
                    key_label=self._enc_key_label,
                    key_id=None,
                )
                sign_pub_raw = self._backend.get_public_key_bytes(
                    key_label=self._sign_key_label,
                    key_id=None,
                )
            except PKCS11KeyNotFoundError as exc:
                raise PKCS11KeyNotFoundError(
                    f"Identity keys not found for app '{app_name}' on slot {slot}: {exc}"
                ) from exc

            self.pub_bytes     = enc_pub_raw
            self.sig_pub_bytes = sign_pub_raw

            self.pub     = X25519PublicKey.from_public_bytes(self.pub_bytes)
            self.sig_pub = Ed25519PublicKey.from_public_bytes(self.sig_pub_bytes)

            self.update_hashes()
            self._is_local_hardware = True

            # See _TokenSigningKeyAdapter: enables this identity to accept
            # inbound RNS links (responder path reads ``sig_prv`` directly).
            self.sig_prv = _TokenSigningKeyAdapter(self)

            # See _TokenResidentPrivateKey: a truthy ``prv`` lets RNS generate
            # token-signed delivery proofs (``RNS.Packet.prove``). ``prv_bytes``
            # stays ``None`` — no in-memory private key is held.
            self.prv = _TOKEN_RESIDENT_PRV

            RNS.log(
                f"App '{app_name}' hardware identity loaded from PKCS#11 slot {slot} "
                f"(hash {RNS.prettyhexrep(self.hash)})",
                RNS.LOG_VERBOSE,
            )

        # ------------------------------------------------------------------
        # Static / class-method overrides
        # ------------------------------------------------------------------

        @staticmethod
        def from_file(path: str) -> "HardwareIdentity | None":
            """
            Load a Reticulum identity.

            This method always loads the public keys from the token, ignoring
            private-key content of any saved identity file. If a public key is
            already saved at *path*, its hash is compared to the token's key to
            warn about mismatches.
            """
            identity = HardwareIdentity(create_keys=False)
            identity._load_keys_from_token()

            # If a saved identity file exists, verify it matches the token.
            if os.path.isfile(path):
                try:
                    with open(path, "rb") as fh:
                        saved_bytes = fh.read()
                    pub_candidate = saved_bytes[: _OriginalIdentity.KEYSIZE // 8]
                    if len(pub_candidate) == _OriginalIdentity.KEYSIZE // 8:
                        saved_pub_hash = _OriginalIdentity.truncated_hash(pub_candidate)
                        if saved_pub_hash != identity.hash:
                            RNS.log(
                                f"Saved identity for app '{app_name}' does not match the PKCS#11 token. "
                                "The token's identity will be used. "
                                f"(saved: {saved_pub_hash.hex()}, token: {identity.hash.hex()})",
                                RNS.LOG_WARNING,
                            )
                except Exception as exc:
                    RNS.log(
                        f"Could not read saved identity at '{path}': {exc}",
                        RNS.LOG_WARNING,
                    )

            return identity

        @staticmethod
        def from_bytes(prv_bytes: bytes) -> "HardwareIdentity | None":
            """
            Create a public-key-only identity from raw bytes.

            This is used internally by Reticulum for interface access control
            and does not touch the PKCS#11 token.
            """
            identity = HardwareIdentity(create_keys=False)
            identity.load_public_key(prv_bytes[: _OriginalIdentity.KEYSIZE // 8])
            return identity

        # ------------------------------------------------------------------
        # Key persistence
        # ------------------------------------------------------------------

        def to_file(self, path: str) -> bool:
            """
            Persist the identity to *path*.

            Only the **public** key is written; the private key always stays in
            the token and is never written to disk.
            """
            return self.pub_to_file(path)

        def get_private_key(self):
            """
            Return the private key bytes.

            For hardware identities the private key never leaves the PKCS#11
            token, so this method returns the public key bytes as a stable,
            unique identifier.  This allows Reticulum to derive its internal
            RPC key without exposing any secret material.
            """
            if self._is_local_hardware:
                return self.get_public_key()
            return super().get_private_key()

        # ------------------------------------------------------------------
        # Signing — delegated to the token
        # ------------------------------------------------------------------

        def sign(self, message: bytes) -> bytes:
            """
            Sign *message* using the Ed25519 key on the PKCS#11 token.

            For remote identities that carry only a public key this raises
            ``KeyError``, identical to the stock ``RNS.Identity`` behaviour.
            """
            if self._is_local_hardware:
                try:
                    return self._backend.sign(
                        message,
                        key_label=self._sign_key_label,
                        key_id=None,
                    )
                except Exception as exc:
                    raise RuntimeError(
                        f"PKCS#11 signing failed for app '{app_name}': {exc}"
                    ) from exc
            # Fall back to software signing for non-hardware instances
            if self.sig_prv is not None:
                return self.sig_prv.sign(message)
            raise KeyError("Signing failed because identity does not hold a private key")

        # ------------------------------------------------------------------
        # Decryption — ECDH in token, HKDF + AES in software
        # ------------------------------------------------------------------

        def decrypt(
            self,
            ciphertext_token: bytes,
            ratchets=None,
            enforce_ratchets: bool = False,
            ratchet_id_receiver=None,
        ):
            """
            Decrypt a Reticulum ciphertext token.

            The X25519 ECDH operation is performed inside the PKCS#11 token so
            the private key never leaves the hardware.  HKDF key derivation and
            AES decryption are performed in software using the extracted shared
            secret, exactly as the stock ``RNS.Identity.decrypt`` does.

            Ratchet-based decryption (using ephemeral software ratchet keys) is
            handled identically to the stock implementation because ratchet
            private keys are ordinary in-memory keys.

            For remote identities that carry only a public key this raises
            ``KeyError``.
            """
            if not self._is_local_hardware:
                # Delegate to stock implementation; it will raise KeyError if
                # no private key is available, which is the expected behaviour.
                return super().decrypt(
                    ciphertext_token,
                    ratchets=ratchets,
                    enforce_ratchets=enforce_ratchets,
                    ratchet_id_receiver=ratchet_id_receiver,
                )

            if len(ciphertext_token) <= _HALF_KEYSIZE:
                RNS.log(
                    "Decryption failed because the token size was invalid.",
                    RNS.LOG_DEBUG,
                ) if RNS.sl(RNS.LOG_DEBUG) else None
                return None

            plaintext = None

            try:
                peer_pub_bytes = ciphertext_token[:_HALF_KEYSIZE]
                ciphertext     = ciphertext_token[_HALF_KEYSIZE:]

                # ---------------------------------------------------------
                # 1. Try ratchet keys (in-memory software keys, same as stock)
                # ---------------------------------------------------------
                if ratchets:
                    for ratchet in ratchets:
                        try:
                            ratchet_prv = X25519PrivateKey.from_private_bytes(ratchet)
                            ratchet_id = _OriginalIdentity._get_ratchet_id(
                                ratchet_prv.public_key().public_bytes()
                            )
                            peer_pub    = X25519PublicKey.from_public_bytes(peer_pub_bytes)
                            shared_key  = ratchet_prv.exchange(peer_pub)
                            plaintext   = self._hw_finish_decrypt(shared_key, ciphertext)
                            if ratchet_id_receiver is not None:
                                ratchet_id_receiver.latest_ratchet_id = ratchet_id
                            break
                        except Exception:
                            pass

                if enforce_ratchets and plaintext is None:
                    RNS.log(
                        f"Decryption with ratchet enforcement by "
                        f"{RNS.prettyhexrep(self.hash)} failed. Dropping packet.",
                        RNS.LOG_DEBUG,
                    ) if RNS.sl(RNS.LOG_DEBUG) else None
                    if ratchet_id_receiver is not None:
                        ratchet_id_receiver.latest_ratchet_id = None
                    return None

                # ---------------------------------------------------------
                # 2. Main path: ECDH inside the token
                # ---------------------------------------------------------
                if plaintext is None:
                    shared_key = self._backend.ecdh_derive(
                        raw_to_ec_point(peer_pub_bytes),
                        key_label=self._enc_key_label,
                        key_id=None,
                    )
                    plaintext = self._hw_finish_decrypt(shared_key, ciphertext)
                    if ratchet_id_receiver is not None:
                        ratchet_id_receiver.latest_ratchet_id = None

            except Exception as exc:
                RNS.log(
                    f"Decryption by {RNS.prettyhexrep(self.hash)} failed: {exc}",
                    RNS.LOG_DEBUG,
                ) if RNS.sl(RNS.LOG_DEBUG) else None
                if ratchet_id_receiver is not None:
                    ratchet_id_receiver.latest_ratchet_id = None

            return plaintext

        def _hw_finish_decrypt(self, shared_key: bytes, ciphertext: bytes):
            """HKDF key derivation + AES decryption (identical to stock)."""
            derived_key = RNS.Cryptography.hkdf(
                length=_OriginalIdentity.DERIVED_KEY_LENGTH,
                derive_from=shared_key,
                salt=self.get_salt(),
                context=self.get_context(),
            )
            token = Token(derived_key)
            return token.decrypt(ciphertext)

        # ------------------------------------------------------------------
        # Repr
        # ------------------------------------------------------------------

        def __repr__(self):
            backing = "hardware" if self._is_local_hardware else "public-key-only"
            return (
                f"<HardwareIdentity [{backing}] "
                f"app='{app_name}' slot={slot} "
                f"hash={self.hexhash or 'unknown'}>"
            )

    HardwareIdentity.__name__ = f"{app_name}Identity"
    HardwareIdentity.__qualname__ = f"{app_name}Identity"
    return HardwareIdentity


# ============================================================================
# Utility functions for multi-app identity creation and querying
# ============================================================================

def create_app_hardware_identity(app_name: str, backend: Optional[PKCS11Backend] = None, slot: Optional[str] = None) -> Optional[_OriginalIdentity]:
    """
    Create a hardware-backed identity for an application.

    Usage:
        from reticulum_pkcs11_identity.identity import create_app_hardware_identity
        identity = create_app_hardware_identity("myapp", backend=backend_instance)
        if identity:
            print(f"Loaded identity: {identity.hexhash}")

    :param app_name: Application name.
    :param backend: PKCS11Backend instance (required).
    :param slot: PIV slot ID, or None to auto-lookup via AppIdentityMapper.
    :returns: HardwareIdentity instance, or None if unavailable.
    """
    try:
        if backend is None:
            raise PKCS11BackendError("Backend must be provided explicitly")
        
        # Create identity class and instantiate
        IdentityClass = make_app_hardware_identity_class(app_name, backend=backend, slot=slot)
        return IdentityClass(create_keys=True)
    except (PKCS11BackendError, PKCS11KeyNotFoundError) as exc:
        RNS.log(
            f"Could not create hardware identity for app '{app_name}': {exc}",
            RNS.LOG_WARNING,
        )
        return None
    except Exception as exc:
        RNS.log(
            f"Unexpected error creating hardware identity for app '{app_name}': {exc}",
            RNS.LOG_ERROR,
        )
        return None


def get_app_identity_keys(app_name: str, backend: Optional[PKCS11Backend] = None, slot: Optional[str] = None) -> Optional[tuple[bytes, bytes]]:
    """
    Get public keys for an application's hardware identity.

    Returns the Ed25519 signing public key and X25519 encryption public key.

    Usage:
        from reticulum_pkcs11_identity.identity import get_app_identity_keys
        keys = get_app_identity_keys("myapp", backend=backend_instance)
        if keys:
            ed_pub, x_pub = keys
            print(f"Signing key: {ed_pub.hex()}")
            print(f"Encryption key: {x_pub.hex()}")

    :param app_name: Application name.
    :param backend: PKCS11Backend instance (required).
    :param slot: PIV slot ID, or None to auto-lookup via AppIdentityMapper.
    :returns: Tuple of (ed25519_public_key, x25519_public_key) as raw bytes,
              or None if keys cannot be retrieved.
    """
    try:
        if backend is None:
            raise PKCS11BackendError("Backend must be provided explicitly")
        
        from .app_identity import AppIdentityMapper

        if slot is None:
            mapper = AppIdentityMapper()
            slot = mapper.get_app_slot(app_name)
            if slot is None:
                return None

        # Key labels follow the app-name convention
        sign_key_label = f"{app_name}-sign"
        enc_key_label = f"{app_name}-enc"

        try:
            ed_pub = backend.get_public_key_bytes(
                key_label=sign_key_label,
                key_id=None,
            )
            x_pub = backend.get_public_key_bytes(
                key_label=enc_key_label,
                key_id=None,
            )
            return (ed_pub, x_pub)
        except PKCS11KeyNotFoundError:
            return None

    except Exception:
        return None
