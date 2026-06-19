"""
PKCS#11 provider detection and selection.

Auto-detects available PKCS#11 modules with fallback chain:
  - libykcs11.dll/libykcs11.so (Yubico PIV Tool)
  - opensc-pkcs11.so (OpenSC - Linux)
  - softhsm2.so (SoftHSM - for testing)

Supports manual override via config or environment variable.
"""

import os
from pathlib import Path

from .exceptions import PKCS11ProviderNotFoundError


# Candidate PKCS#11 modules by priority
_PROVIDERS = [
    # Yubico PIV Tool (libykcs11)
    r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
    r"C:\Program Files (x86)\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
    "/usr/lib/libykcs11.so",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    "/usr/local/lib/libykcs11.so",
    # OpenSC
    r"C:\Program Files\OpenSC Project\OpenSC\opensc-pkcs11.dll",
    r"C:\Program Files (x86)\OpenSC Project\OpenSC\opensc-pkcs11.dll",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    # SoftHSM (testing)
    r"C:\Program Files\SoftHSM2\bin\softhsm2.dll",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
]


def discover_providers(additional_paths: list[str] | None = None) -> list[str]:
    """
    Discover available PKCS#11 providers.

    Args:
        additional_paths: Extra paths to search

    Returns:
        List of available provider paths (by priority)
    """
    candidates = list(_PROVIDERS)
    if additional_paths:
        candidates.extend(additional_paths)

    available = []
    seen = set()

    for path in candidates:
        if not path:
            continue

        # Normalize path
        try:
            normalized = str(Path(path).resolve())
        except Exception:
            normalized = path

        if normalized in seen:
            continue
        seen.add(normalized)

        # Check if file exists
        if os.path.isfile(normalized):
            available.append(normalized)

    return available


def get_default_provider(override: str | None = None) -> str:
    """
    Get the preferred available PKCS#11 provider.

    Priority:
      1. Override (if provided and exists)
      2. Environment variable RNS_PKCS11_PROVIDER
      3. First discovered provider from fallback chain

    Args:
        override: Manual provider path override

    Returns:
        Path to PKCS#11 provider module

    Raises:
        PKCS11ProviderNotFoundError: If no provider found
    """
    # Check override
    if override:
        if os.path.isfile(override):
            return override
        raise PKCS11ProviderNotFoundError(f"Override provider not found: {override}")

    # Check environment
    env_provider = os.environ.get("RNS_PKCS11_PROVIDER")
    if env_provider and os.path.isfile(env_provider):
        return env_provider

    # Try discovery
    providers = discover_providers()
    if providers:
        return providers[0]

    raise PKCS11ProviderNotFoundError(
        "No PKCS#11 provider found. Install Yubico PIV Tool or OpenSC."
    )


def detect_provider_type(provider_path: str) -> str:
    """
    Identify which provider a path refers to.

    Args:
        provider_path: Path to PKCS#11 module

    Returns:
        Provider type: "yubico", "opensc", "softhsm", or "unknown"
    """
    lower = provider_path.lower()

    if "ykcs11" in lower or "yubico" in lower:
        return "yubico"
    elif "opensc" in lower:
        return "opensc"
    elif "softhsm" in lower:
        return "softhsm"
    else:
        return "unknown"
