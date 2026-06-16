#!/usr/bin/env python3
"""Explicit LXMF user identity bootstrap with PKCS#11."""

from __future__ import annotations

import os
import sys

from reticulum_pkcs11_identity import (
    LXMFHardwareIdentityConfig,
    create_lxmf_hardware_identity,
    enumerate_token_inventory,
    format_token_inventory,
)


def _resolve_module_path() -> str | None:
    module = os.environ.get("PKCS11_MODULE")
    if module and os.path.isfile(module):
        return module

    candidates = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def main() -> int:
    module_path = _resolve_module_path()
    if not module_path:
        print(
            "Could not find PKCS#11 module. Set PKCS11_MODULE to your provider path.",
            file=sys.stderr,
        )
        return 1

    token_label = os.environ.get("PKCS11_TOKEN_LABEL", "MyToken")
    config = LXMFHardwareIdentityConfig(
        module_path=module_path,
        token_label=token_label,
        pin_env="LXMF_PKCS11_PIN",
    )

    print("Discovered token inventory:")
    print(format_token_inventory(enumerate_token_inventory(module_paths=[module_path])))
    print()

    handle = create_lxmf_hardware_identity(config, ensure_keys=True)
    try:
        identity = handle.identity
        message = b"hello from lxmf user identity"
        signature = identity.sign(message)
        is_valid = identity.validate(signature, message)
        print(f"LXMF identity hash: {identity.hexhash}")
        print(f"Signature valid: {is_valid}")
    finally:
        handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
