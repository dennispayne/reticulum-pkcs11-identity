"""Plug-in / session bootstrap flow for PKCS#11 hardware identities.

Implements the two-path flow we want when a token appears:

1. **Recognise the token WITHOUT a PIN.** Public keys and certificates are
   public objects, so we can enumerate them on a no-login session to decide
   whether this is a *returning* user (a usable Ed25519 + X25519 identity is
   already present) or a *new* user (no identity yet). We also read the PIN
   flags without logging in, so we never consume the token's last attempt.

2. **Branch on the result:**
   * *Returning user* -> prompt for the **user PIN** and open a session
     (``pin-policy=once`` means one prompt activates the identity for the whole
     session). The PIN is never retried automatically -- three wrong attempts
     would lock the PIV applet.
   * *New user* -> ask **"Provision new user?"** first; only if confirmed do we
     prompt for the **management key** (the PIV "admin" key) and generate the
     keypair. Key generation authenticates with the management key, not the
     PIN, so the PIN counter is untouched.

The orchestration is UI-agnostic: callers inject ``pin_callback``,
``confirm_provision_callback`` and ``management_key_callback``. Console
implementations are provided for a ready-to-run interactive flow, and a
``ykman``-based provisioner implements the (PKCS#11-impossible) X25519 keygen on
YubiKey hardware.

SAFETY: recognition only ever reads PUBLIC keys / certs (enumerating private
keys without login crashes libykcs11). All hardware writes are gated behind an
explicit confirm + management-key prompt, and remain recoverable with
``ykman piv reset``.
"""

from __future__ import annotations

import getpass
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .backend import PKCS11Backend, _load_pkcs11_lib_with_windows_fix
from .exceptions import PKCS11LoginError, PKCS11ProviderNotFoundError
from .pkcs11_provider import get_default_provider

logger = logging.getLogger(__name__)

# EC_PARAMS markers: the curve OID *or* the PrintableString name that libykcs11
# reports (mirrors discovery.py).
_ED25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
_X25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])
_ED25519_PRINTABLE = b"edwards25519"
_X25519_PRINTABLE = b"curve25519"

# DER EC_POINT prefix for 32-byte curve keys.
_EC_POINT_PREFIX = bytes([0x04, 0x20])

# Canonical PIV layout for an RNS hardware identity, as exposed by libykcs11:
#   slot 9a (CKA_ID 0x01) -> Ed25519 signing key
#   slot 9d (CKA_ID 0x03) -> X25519 encryption key
_SIGN_KEY_ID = bytes([0x01])
_ENC_KEY_ID = bytes([0x03])
_SIGN_SLOT = "9a"
_ENC_SLOT = "9d"


class TokenStatus(str, Enum):
    """Outcome of the PIN-less recognition step."""

    ABSENT = "absent"
    PIN_LOCKED = "pin_locked"
    PIN_FINAL_TRY = "pin_final_try"
    RETURNING_USER = "returning_user"  # usable Ed25519 + X25519 identity present
    NEW_USER = "new_user"              # no RNS identity present


@dataclass
class TokenClassification:
    """What we learned about a token without ever asking for a PIN."""

    status: TokenStatus
    token_label: Optional[str] = None
    serial: Optional[str] = None
    has_sign_key: bool = False
    has_enc_key: bool = False
    sign_pub: Optional[bytes] = None      # Ed25519 raw pub from slot 9a, if present
    enc_pub: Optional[bytes] = None       # X25519 raw pub from slot 9d, if present
    identity_hash: Optional[bytes] = None  # RNS address, when the canonical pair exists
    slots: dict[str, str] = field(default_factory=dict)  # CKA_ID hex -> "ed25519"/"x25519"

    @property
    def present(self) -> bool:
        return self.status is not TokenStatus.ABSENT

    @property
    def address(self) -> Optional[str]:
        return self.identity_hash.hex() if self.identity_hash else None


class BootstrapOutcome(str, Enum):
    """Final result of :func:`bootstrap_session`."""

    NO_TOKEN = "no_token"
    PIN_LOCKED = "pin_locked"
    PIN_FINAL_TRY = "pin_final_try"
    ACTIVATED = "activated"
    PIN_INCORRECT = "pin_incorrect"
    CANCELLED = "cancelled"
    PROVISION_DECLINED = "provision_declined"
    PROVISIONED = "provisioned"
    PROVISION_FAILED = "provision_failed"


@dataclass
class BootstrapResult:
    outcome: BootstrapOutcome
    classification: TokenClassification
    backend: Optional[PKCS11Backend] = None
    message: str = ""


# Callback signatures (all UI-agnostic).
PinCallback = Callable[[TokenClassification], Optional[str]]
ConfirmProvisionCallback = Callable[[TokenClassification], bool]
ManagementKeyCallback = Callable[[TokenClassification], Optional[str]]
Provisioner = Callable[..., bool]


# ---------------------------------------------------------------------------
# Step 1: PIN-less recognition
# ---------------------------------------------------------------------------

def _raw_pub_from_object(obj) -> Optional[bytes]:
    """Read CKA_EC_POINT and strip the DER prefix to a raw 32-byte key."""
    from pkcs11 import Attribute

    try:
        ec_point = bytes(obj[Attribute.EC_POINT])
    except Exception:
        return None
    if len(ec_point) == 34 and ec_point[:2] == _EC_POINT_PREFIX:
        return ec_point[2:]
    return ec_point or None


def _compute_identity_hash(enc_pub: bytes, sign_pub: bytes) -> Optional[bytes]:
    """RNS identity address = truncated hash of (X25519_pub || Ed25519_pub)."""
    try:
        import RNS

        ident = RNS.Identity(create_keys=False)
        ident.load_public_key(enc_pub + sign_pub)
        return ident.hash
    except Exception:  # pragma: no cover - RNS optional / shape changes
        return None


def classify_token(
    module_path: str,
    *,
    token_label: Optional[str] = None,
) -> TokenClassification:
    """Recognise a token without logging in (no PIN consumed).

    Reads the PIN flags and enumerates **public keys only** (never private keys
    -- that crashes libykcs11 pre-login) to decide new vs. returning user.
    """
    try:
        lib = _load_pkcs11_lib_with_windows_fix(module_path)
    except Exception as exc:
        logger.debug("Could not load PKCS#11 module %s: %s", module_path, exc)
        return TokenClassification(status=TokenStatus.ABSENT)

    from pkcs11 import Attribute, ObjectClass, TokenFlag

    token = None
    try:
        for slot in lib.get_slots(token_present=True):
            candidate = slot.get_token()
            if token_label and (candidate.label or "").strip() != token_label.strip():
                continue
            token = candidate
            break
    except Exception as exc:  # pragma: no cover - environment specific
        logger.debug("Slot enumeration failed: %s", exc)
        return TokenClassification(status=TokenStatus.ABSENT)

    if token is None:
        return TokenClassification(status=TokenStatus.ABSENT)

    label = (token.label or "").strip() or None
    serial = None
    try:
        serial_attr = token.serial
        serial = serial_attr.decode() if isinstance(serial_attr, bytes) else str(serial_attr)
        serial = serial.strip() or None
    except Exception:
        serial = None

    # --- PIN flags, read WITHOUT logging in ---
    try:
        flags = token.flags
    except Exception:
        flags = 0
    if flags & TokenFlag.USER_PIN_LOCKED:
        return TokenClassification(
            status=TokenStatus.PIN_LOCKED, token_label=label, serial=serial
        )
    final_try = bool(flags & TokenFlag.USER_PIN_FINAL_TRY)

    # --- enumerate PUBLIC keys (read-only, no login) ---
    slots: dict[str, str] = {}
    sign_pub: Optional[bytes] = None
    enc_pub: Optional[bytes] = None
    try:
        with token.open(rw=False) as session:
            for obj in session.get_objects({ObjectClass.PUBLIC_KEY: None}):
                try:
                    kid = bytes(obj[Attribute.ID])
                    ec_params = bytes(obj[Attribute.EC_PARAMS])
                except Exception:
                    continue
                if _ED25519_OID in ec_params or _ED25519_PRINTABLE in ec_params:
                    slots[kid.hex()] = "ed25519"
                    if kid == _SIGN_KEY_ID:
                        sign_pub = _raw_pub_from_object(obj)
                elif _X25519_OID in ec_params or _X25519_PRINTABLE in ec_params:
                    slots[kid.hex()] = "x25519"
                    if kid == _ENC_KEY_ID:
                        enc_pub = _raw_pub_from_object(obj)
    except Exception as exc:  # pragma: no cover - environment specific
        logger.debug("Public-key enumeration failed: %s", exc)

    has_sign = any(v == "ed25519" for v in slots.values())
    has_enc = any(v == "x25519" for v in slots.values())
    is_returning = has_sign and has_enc

    identity_hash = None
    if sign_pub and enc_pub:
        identity_hash = _compute_identity_hash(enc_pub, sign_pub)

    if is_returning and final_try:
        # Surface the danger instead of auto-prompting for a PIN with one try left.
        status = TokenStatus.PIN_FINAL_TRY
    elif is_returning:
        status = TokenStatus.RETURNING_USER
    else:
        status = TokenStatus.NEW_USER

    return TokenClassification(
        status=status,
        token_label=label,
        serial=serial,
        has_sign_key=has_sign,
        has_enc_key=has_enc,
        sign_pub=sign_pub,
        enc_pub=enc_pub,
        identity_hash=identity_hash,
        slots=slots,
    )


# ---------------------------------------------------------------------------
# Step 2: orchestration
# ---------------------------------------------------------------------------

def bootstrap_session(
    module_path: str,
    *,
    token_label: Optional[str] = None,
    pin_callback: PinCallback,
    confirm_provision_callback: ConfirmProvisionCallback,
    management_key_callback: ManagementKeyCallback,
    provisioner: Optional[Provisioner] = None,
    classification: Optional[TokenClassification] = None,
    backend_factory: Callable[..., PKCS11Backend] = PKCS11Backend,
) -> BootstrapResult:
    """Recognise the token and run the returning- or new-user flow.

    :param classification: precomputed classification (skips re-recognition;
        mainly for testing/UIs that already classified the token).
    :param backend_factory: injectable for testing; defaults to ``PKCS11Backend``.
    """
    if classification is None:
        classification = classify_token(module_path, token_label=token_label)

    status = classification.status

    if status is TokenStatus.ABSENT:
        return BootstrapResult(
            BootstrapOutcome.NO_TOKEN, classification,
            message="No PKCS#11 token is present.",
        )
    if status is TokenStatus.PIN_LOCKED:
        return BootstrapResult(
            BootstrapOutcome.PIN_LOCKED, classification,
            message="The token PIN is locked. Reset the PIV applet (`ykman piv reset`).",
        )
    if status is TokenStatus.PIN_FINAL_TRY:
        return BootstrapResult(
            BootstrapOutcome.PIN_FINAL_TRY, classification,
            message="The PIN is on its FINAL try; refusing to prompt automatically "
                    "to avoid a lockout.",
        )
    if status is TokenStatus.RETURNING_USER:
        return _activate_returning(
            module_path, token_label, classification, pin_callback, backend_factory
        )
    # NEW_USER
    return _provision_new(
        module_path, token_label, classification,
        confirm_provision_callback, management_key_callback, provisioner,
    )


def _activate_returning(
    module_path: str,
    token_label: Optional[str],
    classification: TokenClassification,
    pin_callback: PinCallback,
    backend_factory: Callable[..., PKCS11Backend],
) -> BootstrapResult:
    pin = pin_callback(classification)
    if not pin:
        return BootstrapResult(
            BootstrapOutcome.CANCELLED, classification, message="PIN entry cancelled."
        )

    backend = backend_factory(
        module_path=module_path,
        token_label=classification.token_label or token_label,
    )
    try:
        # One login attempt. NEVER retry on a wrong PIN -- three failures lock
        # the PIV applet.
        backend.open_session(pin=pin)
    except PKCS11LoginError as exc:
        message = str(exc)
        if "lock" in message.lower():
            return BootstrapResult(
                BootstrapOutcome.PIN_LOCKED, classification,
                message="The token PIN is now locked. Reset with `ykman piv reset`.",
            )
        return BootstrapResult(
            BootstrapOutcome.PIN_INCORRECT, classification,
            message="Incorrect PIN. Not retrying automatically (avoids lockout).",
        )
    except Exception as exc:  # pragma: no cover - environment specific
        return BootstrapResult(
            BootstrapOutcome.CANCELLED, classification,
            message=f"Could not open a session: {exc}",
        )

    addr = classification.address or "(address unavailable)"
    return BootstrapResult(
        BootstrapOutcome.ACTIVATED, classification, backend=backend,
        message=f"Hardware identity activated ({addr}).",
    )


def _provision_new(
    module_path: str,
    token_label: Optional[str],
    classification: TokenClassification,
    confirm_provision_callback: ConfirmProvisionCallback,
    management_key_callback: ManagementKeyCallback,
    provisioner: Optional[Provisioner],
) -> BootstrapResult:
    if not confirm_provision_callback(classification):
        return BootstrapResult(
            BootstrapOutcome.PROVISION_DECLINED, classification,
            message="Provisioning declined; no changes made to the token.",
        )

    management_key = management_key_callback(classification)
    if management_key is None:
        return BootstrapResult(
            BootstrapOutcome.CANCELLED, classification,
            message="Management-key entry cancelled; no changes made to the token.",
        )

    provision = provisioner or provision_identity_via_ykman
    try:
        ok = provision(
            token_label=classification.token_label or token_label,
            management_key=management_key or None,  # "" -> token default
        )
    except Exception as exc:  # pragma: no cover - environment specific
        return BootstrapResult(
            BootstrapOutcome.PROVISION_FAILED, classification,
            message=f"Provisioning failed: {exc}",
        )

    if not ok:
        return BootstrapResult(
            BootstrapOutcome.PROVISION_FAILED, classification,
            message="Provisioning failed (see logs).",
        )

    # Re-recognise so the caller sees the freshly created identity.
    new_classification = classify_token(
        module_path, token_label=classification.token_label or token_label
    )
    return BootstrapResult(
        BootstrapOutcome.PROVISIONED, new_classification,
        message="Provisioned a new identity (Ed25519 in 9a + X25519 in 9d). "
                "Enter the PIN next time to activate it.",
    )


# ---------------------------------------------------------------------------
# Hardware provisioner (X25519 keygen is PKCS#11-impossible on YubiKey, so we
# drive ykman -- the management key, not the PIN, authorises this).
# ---------------------------------------------------------------------------

def _find_ykman() -> Optional[str]:
    candidates = [
        r"C:\Program Files\Yubico\YubiKey Manager CLI\ykman.exe",
        r"C:\Program Files (x86)\Yubico\YubiKey Manager CLI\ykman.exe",
        "/usr/bin/ykman",
        "/usr/local/bin/ykman",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    # Fall back to PATH lookup.
    from shutil import which

    return which("ykman")


def provision_identity_via_ykman(
    *,
    token_label: Optional[str] = None,
    management_key: Optional[str] = None,
    ykman_path: Optional[str] = None,
    sign_slot: str = _SIGN_SLOT,
    enc_slot: str = _ENC_SLOT,
    pin_policy: str = "once",
    touch_policy: str = "never",
) -> bool:
    """Generate Ed25519 (sign) + X25519 (enc) on the YubiKey via ``ykman``.

    Authenticated by the **management key** (``management_key=None`` lets ykman
    use the token's default). Overwrites the target slots, so callers must gate
    this behind explicit user confirmation (the bootstrap flow does).
    """
    ykman = ykman_path or _find_ykman()
    if not ykman:
        logger.error("ykman not found; cannot provision X25519 on hardware.")
        return False

    env = os.environ.copy()
    # ykman's data dir can be ACL-locked on Windows; point it at a writable temp.
    env.setdefault("XDG_DATA_HOME", os.path.join(tempfile.gettempdir(), "rnid_ykman_data"))

    def _generate(algorithm: str, slot: str) -> bool:
        cmd = [
            ykman, "piv", "keys", "generate",
            "-a", algorithm,
            "--pin-policy", pin_policy,
            "--touch-policy", touch_policy,
        ]
        if management_key:
            cmd += ["-m", management_key]
        # Public key goes to stdout; we don't need to keep it.
        cmd += [slot, "-"]
        try:
            proc = subprocess.run(
                cmd, env=env, capture_output=True, text=True, timeout=60
            )
        except Exception as exc:  # pragma: no cover - environment specific
            logger.error("ykman %s keygen failed to launch: %s", algorithm, exc)
            return False
        if proc.returncode != 0:
            logger.error(
                "ykman %s keygen failed (rc=%s): %s",
                algorithm, proc.returncode, proc.stderr.strip(),
            )
            return False
        return True

    return _generate("ed25519", sign_slot) and _generate("x25519", enc_slot)


# ---------------------------------------------------------------------------
# Console callbacks + interactive entry point
# ---------------------------------------------------------------------------

def console_pin_callback(classification: TokenClassification) -> Optional[str]:
    addr = classification.address or "(address unavailable)"
    label = classification.token_label or "token"
    print(f"\nReturning identity on {label}: {addr}")
    try:
        pin = getpass.getpass("Enter PIN to activate (blank to cancel): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return pin or None


def console_confirm_provision_callback(classification: TokenClassification) -> bool:
    label = classification.token_label or "token"
    print(f"\nNo Reticulum identity found on {label}.")
    try:
        answer = input("Provision new user? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def console_management_key_callback(classification: TokenClassification) -> Optional[str]:
    print("Provisioning needs the PIV management key (the admin key).")
    try:
        key = getpass.getpass("Management key (blank = token default, Ctrl-C to cancel): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return key  # "" means "use the token default"


def run_interactive_bootstrap(
    module_path: Optional[str] = None,
    *,
    token_label: Optional[str] = None,
) -> BootstrapResult:
    """Drive the full plug-in flow on the console."""
    if module_path is None:
        module_path = get_default_provider()

    result = bootstrap_session(
        module_path,
        token_label=token_label,
        pin_callback=console_pin_callback,
        confirm_provision_callback=console_confirm_provision_callback,
        management_key_callback=console_management_key_callback,
    )
    print(result.message)
    return result


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="rnidsetup",
        description="Recognise a plugged-in PKCS#11 token and either activate "
                    "the existing identity (PIN) or provision a new one "
                    "(confirm + management key).",
    )
    parser.add_argument("--provider", help="PKCS#11 module path (auto-detected by default).")
    parser.add_argument("--token-label", help="Restrict to a token with this label.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    try:
        module_path = args.provider or get_default_provider()
    except PKCS11ProviderNotFoundError as exc:
        print(exc)
        return 2

    result = run_interactive_bootstrap(module_path, token_label=args.token_label)
    return 0 if result.outcome in (
        BootstrapOutcome.ACTIVATED, BootstrapOutcome.PROVISIONED
    ) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
