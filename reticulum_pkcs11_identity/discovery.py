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

"""Provider and token discovery helpers for PKCS#11 identity selection.

Provides:
  - Module discovery (libykcs11, opensc, softhsm)
  - Token enumeration
  - PIV slot probing (9a, 9c, 9d, 9e)
  - Key type detection (Ed25519, X25519)
"""

from __future__ import annotations

import logging
import os

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass, SlotFlag

_logger = logging.getLogger(__name__)

# DER-encoded OID prefixes for Edwards curves
# Ed25519 OID 1.3.101.112 → 06 03 2B 65 70
_ED25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
# X25519 OID 1.3.101.110 → 06 03 2B 65 6E
_X25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])

# PIV slot identifiers
PIV_SLOTS = {
    "9a": "AUTHENTICATION",
    "9c": "SIGNATURE",
    "9d": "KEY_MANAGEMENT",
    "9e": "CARD_AUTHENTICATION",
}

_DEFAULT_MODULE_CANDIDATES = [
    # Windows
    r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
    r"C:\Program Files (x86)\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
    r"C:\Program Files\OpenSC Project\OpenSC\opensc-pkcs11.dll",
    r"C:\Program Files (x86)\OpenSC Project\OpenSC\opensc-pkcs11.dll",
    r"C:\Program Files\SoftHSM2\bin\softhsm2.dll",
    # Linux - SoftHSM2
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    # Linux - OpenSC (PIV on YubiKey and other smartcards)
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    # Linux - Yubico PIV toolchain
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    "/usr/lib/libykcs11.so",
    "/usr/local/lib/libykcs11.so",
    # Linux - p11-kit aggregate proxy
    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
    "/usr/lib/pkcs11/p11-kit-client.so",
    "/usr/lib/pkcs11/p11-kit-trust.so",
]

_PROVIDER_HINTS = [
    ("softhsm", "SoftHSM2"),
    ("opensc", "OpenSC / Smartcard"),
    ("ykcs11", "YubiKey PIV"),
    ("yubico", "YubiKey"),
    ("p11-kit", "p11-kit proxy"),
]

_PROVIDER_TYPES = [
    ("softhsm", "software"),
    ("opensc", "hardware"),
    ("ykcs11", "hardware"),
    ("yubico", "hardware"),
]

_PROVIDER_TYPE_SORT = {
    "hardware": 0,
    "unknown": 1,
    "software": 2,
}


def _has_public_key(session, label: str) -> bool:
    if not label:
        return False
    try:
        session.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            key_type=KeyType.EC_EDWARDS,
            label=label,
        )
        return True
    except pkcs11.exceptions.NoSuchKey:
        return False
    except pkcs11.exceptions.MultipleObjectsReturned:
        return True


def _provider_hint(module_path: str) -> str:
    lower = module_path.lower()
    for needle, hint in _PROVIDER_HINTS:
        if needle in lower:
            return hint
    return "Unknown provider"


def _provider_type(module_path: str) -> str:
    lower = module_path.lower()
    for needle, ptype in _PROVIDER_TYPES:
        if needle in lower:
            return ptype
    return "unknown"


def _is_hardware_provider(module_path: str) -> bool:
    """
    Determine if a PKCS#11 provider is a hardware provider.

    Checks if the module has slots with CKF_HW_SLOT flag set.
    Handles load errors gracefully by checking module name hints first,
    then attempting to query slot flags.

    Args:
        module_path: Path to PKCS#11 module

    Returns:
        True if hardware provider detected, False otherwise
    """
    try:
        lib = pkcs11.lib(module_path)
    except Exception:
        return False

    try:
        slots = list(lib.get_slots())
    except Exception:
        return False

    for slot in slots:
        try:
            if slot.flags & SlotFlag.HW_SLOT:
                return True
        except Exception:
            continue

    return False


def _get_provider_label(module_path: str) -> str:
    """
    Extract a human-readable label for a provider.

    Returns a label based on the module filename and type hints.

    Args:
        module_path: Path to PKCS#11 module

    Returns:
        Human-readable provider label
    """
    hint = _provider_hint(module_path)
    return hint


def categorize_providers(
    additional_paths: list[str] | None = None,
) -> dict:
    """
    Discover and categorize PKCS#11 providers into hardware, software, and unknown.

    Finds all available PKCS#11 modules and categorizes them by interrogating
    the CKF_HW_SLOT flag from each provider's slots.

    Args:
        additional_paths: Extra provider paths to include in discovery

    Returns:
        Dict with keys "hardware", "software", "unknown", each containing a list
        of provider info dicts with keys: "name", "path", "label"

    Example:
        >>> result = categorize_providers()
        >>> for provider in result["hardware"]:
        ...     print(f"Hardware: {provider['name']} at {provider['path']}")
    """
    providers = {
        "hardware": [],
        "software": [],
        "unknown": [],
    }

    discovered = discover_pkcs11_modules(additional_paths)

    for module_path in discovered:
        filename = os.path.basename(module_path)
        name = os.path.splitext(filename)[0]
        label = _get_provider_label(module_path)

        provider_info = {
            "name": name,
            "path": module_path,
            "label": label,
        }

        prov_type = _provider_type(module_path)

        if prov_type == "hardware":
            providers["hardware"].append(provider_info)
        elif prov_type == "software":
            providers["software"].append(provider_info)
        else:
            if _is_hardware_provider(module_path):
                providers["hardware"].append(provider_info)
            else:
                providers["unknown"].append(provider_info)

    return providers


def select_provider(
    categorized: dict,
) -> dict | None:
    """
    Select a provider from categorized providers with smart logic.

    Selection rules:
      - If exactly 1 hardware provider: select it (log info)
      - If >1 hardware provider: log warning, return None
      - If 0 hardware but software exists: select first (log info)
      - If nothing available: log warning, return None

    Args:
        categorized: Output from categorize_providers()

    Returns:
        Selected provider info dict or None if selection failed/ambiguous
    """
    hardware = categorized.get("hardware", [])
    software = categorized.get("software", [])
    unknown = categorized.get("unknown", [])

    if len(hardware) == 1:
        provider = hardware[0]
        _logger.info(
            f"Selected hardware provider: {provider['name']} "
            f"({provider['label']}) at {provider['path']}"
        )
        return provider

    if len(hardware) > 1:
        names = ", ".join(p["name"] for p in hardware)
        _logger.warning(
            f"Multiple hardware providers detected ({names}). "
            "Please specify which provider to use in configuration."
        )
        return None

    if software:
        provider = software[0]
        _logger.info(
            f"No hardware provider found. Using software provider: "
            f"{provider['name']} ({provider['label']}) at {provider['path']}"
        )
        return provider

    _logger.warning("No PKCS#11 providers found. Please install a provider.")
    return None


# ============================================================================
# PIV Slot Discovery Functions (New API)
# ============================================================================


def discover_pkcs11_modules(additional_paths: list[str] | None = None) -> list[str]:
    """
    Discover available PKCS#11 modules.

    Args:
        additional_paths: Extra paths to search

    Returns:
        List of available module paths
    """
    candidates = list(_DEFAULT_MODULE_CANDIDATES)
    if additional_paths:
        candidates.extend(additional_paths)

    seen = set()
    discovered = []
    for path in candidates:
        if not path:
            continue
        normalized = os.path.realpath(path)
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.isfile(normalized):
            discovered.append(normalized)
    return discovered


def list_tokens(module_path: str) -> list[dict]:
    """
    List all tokens available on a PKCS#11 module.

    Args:
        module_path: Path to PKCS#11 module

    Returns:
        List of dicts with token_label, serial, slot_id
    """
    tokens = []
    try:
        lib = pkcs11.lib(module_path)
    except Exception:
        return tokens

    try:
        slots = list(lib.get_slots(token_present=True))
    except Exception:
        return tokens

    for slot in slots:
        try:
            token = slot.get_token()
            label = (getattr(token, "label", "") or "").strip()
            serial = (getattr(token, "serial", "") or "").strip()
            tokens.append({
                "slot_id": slot.slot_id,
                "token_label": label,
                "serial": serial,
            })
        except Exception:
            continue

    return tokens


def probe_piv_slots(session) -> dict:
    """
    Probe PIV slots (9a, 9c, 9d, 9e) for key occupancy.

    Args:
        session: PKCS#11 session object

    Returns:
        Dict mapping slot ID to occupancy info:
        {
            "9a": {"occupied": bool, "has_ed25519": bool, "has_x25519": bool},
            "9c": {"occupied": bool, "has_ed25519": bool, "has_x25519": bool},
            ...
        }
    """
    slots_status = {}
    for slot_id in PIV_SLOTS.keys():
        slots_status[slot_id] = {
            "occupied": False,
            "has_ed25519": False,
            "has_x25519": False,
        }

        # Check for Ed25519
        if has_ed25519_key(session, slot_id):
            slots_status[slot_id]["occupied"] = True
            slots_status[slot_id]["has_ed25519"] = True

        # Check for X25519
        if has_x25519_key(session, slot_id):
            slots_status[slot_id]["occupied"] = True
            slots_status[slot_id]["has_x25519"] = True

    return slots_status


def has_ed25519_key(session, slot: str) -> bool:
    """
    Check if a PIV slot contains an Ed25519 key.

    Args:
        session: PKCS#11 session
        slot: PIV slot ID (e.g., "9a", "9c")

    Returns:
        True if Ed25519 key found, False otherwise
    """
    if slot not in PIV_SLOTS:
        return False

    try:
        # Query for public keys with Edwards curve
        keys = list(session.get_objects({
            ObjectClass.PUBLIC_KEY: None,
            KeyType.EC_EDWARDS: None,
        }))

        for key in keys:
            try:
                # Check if this key's EC_PARAMS contains Ed25519 OID
                ec_params = key.get(Attribute.EC_PARAMS)
                if ec_params and _ED25519_OID in bytes(ec_params):
                    return True
            except Exception:
                continue

        return False
    except Exception:
        return False


def has_x25519_key(session, slot: str) -> bool:
    """
    Check if a PIV slot contains an X25519 key.

    Args:
        session: PKCS#11 session
        slot: PIV slot ID (e.g., "9a", "9c")

    Returns:
        True if X25519 key found, False otherwise
    """
    if slot not in PIV_SLOTS:
        return False

    try:
        # Query for public keys with Edwards curve
        keys = list(session.get_objects({
            ObjectClass.PUBLIC_KEY: None,
            KeyType.EC_EDWARDS: None,
        }))

        for key in keys:
            try:
                # Check if this key's EC_PARAMS contains X25519 OID
                ec_params = key.get(Attribute.EC_PARAMS)
                if ec_params and _X25519_OID in bytes(ec_params):
                    return True
            except Exception:
                continue

        return False
    except Exception:
        return False


# ============================================================================
# Backward-compatible legacy functions
# ============================================================================


def discover_module_paths(additional_paths: list[str] | None = None) -> list[str]:
    """Return existing PKCS#11 module paths from built-in and user-provided candidates."""
    return discover_pkcs11_modules(additional_paths)


def enumerate_token_inventory(
    module_paths: list[str] | None = None,
    *,
    token_label: str | None = None,
    sign_key_label: str = "lxmf-sign",
    enc_key_label: str = "lxmf-enc",
) -> list[dict]:
    """
    Enumerate available PKCS#11 tokens across module paths.

    Returns one dict per token with provider hints and identity readiness:
      - module_path
      - provider_hint
      - provider_type ("hardware", "software", or "unknown")
      - slot_id
      - token_label
      - serial
      - has_sign_key
      - has_enc_key
      - identity_status ("ready", "partial", "missing", or "unknown")
      - error (optional string if module/token introspection failed)
    """
    discovered = module_paths or discover_module_paths()
    rows = []

    for module_path in discovered:
        provider = _provider_hint(module_path)
        provider_type = _provider_type(module_path)

        try:
            lib = pkcs11.lib(module_path)
        except Exception as exc:
            rows.append(
                {
                    "module_path": module_path,
                    "provider_hint": provider,
                    "provider_type": provider_type,
                    "slot_id": None,
                    "token_label": None,
                    "serial": None,
                    "has_sign_key": None,
                    "has_enc_key": None,
                    "identity_status": "unknown",
                    "error": f"module load failed: {exc}",
                }
            )
            continue

        try:
            slots = list(lib.get_slots(token_present=True))
        except Exception as exc:
            rows.append(
                {
                    "module_path": module_path,
                    "provider_hint": provider,
                    "provider_type": provider_type,
                    "slot_id": None,
                    "token_label": None,
                    "serial": None,
                    "has_sign_key": None,
                    "has_enc_key": None,
                    "identity_status": "unknown",
                    "error": f"slot enumeration failed: {exc}",
                }
            )
            continue

        for slot in slots:
            try:
                token = slot.get_token()
            except Exception as exc:
                rows.append(
                    {
                        "module_path": module_path,
                        "provider_hint": provider,
                        "provider_type": provider_type,
                        "slot_id": slot.slot_id,
                        "token_label": None,
                        "serial": None,
                        "has_sign_key": None,
                        "has_enc_key": None,
                        "identity_status": "unknown",
                        "error": f"token read failed: {exc}",
                    }
                )
                continue

            label = (getattr(token, "label", "") or "").strip()
            if token_label and label != token_label:
                continue

            row = {
                "module_path": module_path,
                "provider_hint": provider,
                "provider_type": provider_type,
                "slot_id": slot.slot_id,
                "token_label": label,
                "serial": (getattr(token, "serial", "") or "").strip(),
                "has_sign_key": None,
                "has_enc_key": None,
                "identity_status": "unknown",
            }

            try:
                session = token.open(rw=False)
                try:
                    has_sign = _has_public_key(session, sign_key_label)
                    has_enc = _has_public_key(session, enc_key_label)
                finally:
                    session.close()

                row["has_sign_key"] = has_sign
                row["has_enc_key"] = has_enc

                if has_sign and has_enc:
                    row["identity_status"] = "ready"
                elif has_sign or has_enc:
                    row["identity_status"] = "partial"
                else:
                    row["identity_status"] = "missing"
            except Exception as exc:
                row["error"] = f"key probe failed: {exc}"

            rows.append(row)

    rows.sort(
        key=lambda item: (
            _PROVIDER_TYPE_SORT.get(item.get("provider_type") or "unknown", 1),
            item.get("provider_hint") or "",
            str(item.get("token_label") or ""),
            str(item.get("serial") or ""),
            item.get("slot_id") if item.get("slot_id") is not None else -1,
        )
    )
    return rows


def format_token_inventory(rows: list[dict]) -> str:
    """Format discovery rows as a user-facing numbered list with provider hints."""
    if not rows:
        return "No PKCS#11 providers/tokens were discovered."

    lines = []
    for idx, row in enumerate(rows, start=1):
        provider = row.get("provider_hint") or "Unknown provider"
        provider_type = row.get("provider_type") or "unknown"
        module_path = row.get("module_path") or "<unknown module>"
        token_label = row.get("token_label") or "<unknown token>"
        serial = row.get("serial") or "<unknown serial>"
        slot = row.get("slot_id")
        status = row.get("identity_status") or "unknown"
        hint = f"sign={row.get('has_sign_key')}, enc={row.get('has_enc_key')}"

        line = (
            f"[{idx}] provider={provider} ({provider_type}) token={token_label} serial={serial} "
            f"slot={slot} status={status} ({hint})"
        )
        lines.append(line)
        lines.append(f"    module: {module_path}")
        if row.get("error"):
            lines.append(f"    note: {row['error']}")

    return "\n".join(lines)
