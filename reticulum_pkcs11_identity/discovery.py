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

"""Provider and token discovery helpers for LXMF PKCS#11 identity selection."""

from __future__ import annotations

import os

import pkcs11
from pkcs11 import KeyType, ObjectClass

_DEFAULT_MODULE_CANDIDATES = [
    # SoftHSM2
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    # OpenSC (PIV on YubiKey and other smartcards)
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    # Yubico PIV toolchain
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    "/usr/lib/libykcs11.so",
    "/usr/local/lib/libykcs11.so",
    # p11-kit aggregate proxy
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


def discover_module_paths(additional_paths: list[str] | None = None) -> list[str]:
    """Return existing PKCS#11 module paths from built-in and user-provided candidates."""
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
