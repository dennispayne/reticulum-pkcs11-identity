#!/usr/bin/env python3
"""
Example: Generic setup pattern for any Reticulum app with hardware identity.

ZERO APP CHANGES PRINCIPLE:
  Any Reticulum app can support hardware identities with just ONE addition:
  a call to create_app_hardware_identity("app_name"). No other changes needed.

This example shows THREE different setup approaches:
  1. INTERACTIVE:     User enters PIN when app starts (interactive terminal)
  2. ENVIRONMENT:     PIN in environment variable (headless/CI)
  3. CONFIG_FILE:     PIN in secure config file (daemon/service)

Setup Flow:
  1. Admin installs package: pip install reticulum-pkcs11-identity
  2. Admin chooses setup approach (interactive, env, or config)
  3. App calls one function at startup
  4. Done - hardware backing is transparent

Key Features:
  - Graceful fallback (software if hardware unavailable)
  - Error handling and diagnostics
  - Multi-app slot management
  - Explicit verification (optional)
"""

from __future__ import annotations

import os
import sys
import getpass
from pathlib import Path
from typing import Optional

from reticulum_pkcs11_identity import (
    create_app_hardware_identity,
    get_app_identity_keys,
    discover_module_paths,
    enumerate_token_inventory,
    format_token_inventory,
)
from reticulum_pkcs11_identity.exceptions import (
    PKCS11ConfigError,
    PKCS11IdentityError,
    PKCS11LoginError,
)


# =============================================================================
# SETUP APPROACH 1: INTERACTIVE (User enters PIN at startup)
# =============================================================================


def setup_interactive(app_name: str) -> bool:
    """
    Interactive setup: User enters PIN when app starts.

    Best for: Desktop apps, development, user-facing applications.

    Flow:
      1. User starts app
      2. App prompts: "Enter PKCS#11 PIN:"
      3. User types PIN (masked)
      4. App creates hardware identity
      5. PIN cached in token session (never written to disk)

    Args:
        app_name: Unique app identifier (e.g., "sideband", "meshchat")

    Returns:
        True if hardware identity created/available, False otherwise.
    """
    print("\n" + "=" * 70)
    print("SETUP APPROACH 1: INTERACTIVE PIN ENTRY")
    print("=" * 70)

    print(f"\nSetting up hardware identity for: {app_name}")
    print()

    # Step 1: Discover hardware
    print("Step 1: Discovering PKCS#11 tokens...")
    try:
        modules = discover_module_paths()
        if not modules:
            print("  ✗ No PKCS#11 modules found")
            print("  Install SoftHSM or connect a YubiKey")
            return False

        print(f"  ✓ Found {len(modules)} PKCS#11 module(s)")

        # Show token inventory
        inventory = enumerate_token_inventory(module_paths=modules)
        if not inventory:
            print("  ✗ No tokens found in modules")
            return False

        print("\nAvailable tokens:")
        print(format_token_inventory(inventory))

    except Exception as e:
        print(f"  ✗ Discovery error: {e}")
        return False

    # Step 2: Get PIN interactively
    print("Step 2: Enter PKCS#11 PIN")
    pin = getpass.getpass("  PIN (will not be echoed): ", stream=sys.stderr)

    if not pin:
        print("  ✗ PIN cannot be empty")
        return False

    print("  ✓ PIN received (stored in secure token session)")

    # Step 3: Set PIN in environment (for this session only)
    os.environ["RNS_PKCS11_PIN"] = pin

    # Step 4: Create hardware identity
    print(f"\nStep 3: Creating hardware identity for {app_name}...")
    try:
        hw_identity = create_app_hardware_identity(app_name, ensure_keys=True)

        if hw_identity is not None:
            print(f"  ✓ Hardware identity created successfully")
            print(f"    App: {app_name}")
            print(f"    Slot: {hw_identity.slot}")

            # Get and display keys
            ed_pub, x_pub = hw_identity.get_public_keys()
            print(f"    Ed25519 public (first 16 bytes): {ed_pub[:16].hex()}")
            print(f"    X25519 public (first 16 bytes):  {x_pub[:16].hex()}")

            return True
        else:
            print(f"  ✗ Failed to create hardware identity")
            return False

    except PKCS11LoginError as e:
        print(f"  ✗ PIN incorrect or login failed: {e}")
        return False
    except PKCS11IdentityError as e:
        print(f"  ✗ Identity error: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False


# =============================================================================
# SETUP APPROACH 2: ENVIRONMENT VARIABLE (Headless/CI)
# =============================================================================


def setup_environment_variable(app_name: str) -> bool:
    """
    Environment variable setup: PIN in RNS_PKCS11_PIN.

    Best for: Headless apps, CI/CD, Docker containers, system daemons.

    Configuration:
      export RNS_PKCS11_PIN=123456
      python your_app.py

    Or in .env file:
      RNS_PKCS11_PIN=123456

    Or in systemd service:
      [Service]
      Environment="RNS_PKCS11_PIN=123456"
      ExecStart=/usr/bin/python /path/to/app.py

    Args:
        app_name: Unique app identifier

    Returns:
        True if hardware identity created/available, False otherwise.
    """
    print("\n" + "=" * 70)
    print("SETUP APPROACH 2: ENVIRONMENT VARIABLE")
    print("=" * 70)

    print(f"\nSetting up hardware identity for: {app_name}")
    print()

    # Step 1: Check if PIN is in environment
    print("Step 1: Checking for RNS_PKCS11_PIN environment variable...")
    pin = os.environ.get("RNS_PKCS11_PIN")

    if not pin:
        print("  ✗ RNS_PKCS11_PIN not set")
        print("\nTo use this approach:")
        print("  export RNS_PKCS11_PIN=<your_pin>")
        print("  python your_app.py")
        return False

    print("  ✓ PIN found in environment")

    # Step 2: Create hardware identity
    print(f"\nStep 2: Creating hardware identity for {app_name}...")
    try:
        hw_identity = create_app_hardware_identity(app_name, ensure_keys=True)

        if hw_identity is not None:
            print(f"  ✓ Hardware identity created successfully")
            print(f"    App: {app_name}")
            print(f"    Slot: {hw_identity.slot}")

            ed_pub, x_pub = hw_identity.get_public_keys()
            print(f"    Ed25519 public (first 16 bytes): {ed_pub[:16].hex()}")
            print(f"    X25519 public (first 16 bytes):  {x_pub[:16].hex()}")

            return True
        else:
            print(f"  ✗ Failed to create hardware identity")
            return False

    except PKCS11LoginError as e:
        print(f"  ✗ PIN incorrect: {e}")
        return False
    except PKCS11IdentityError as e:
        print(f"  ✗ Identity error: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False


# =============================================================================
# SETUP APPROACH 3: SECURE CONFIG FILE (Daemon/Service)
# =============================================================================


def setup_config_file(app_name: str) -> bool:
    """
    Config file setup: PIN stored in secure config file.

    Best for: System daemons, installed services, long-running processes.

    Configuration:
      1. Create ~/.config/reticulum/pkcs11_pin.conf
      2. Make it owned by app user: chown user:user pkcs11_pin.conf
      3. Make it only readable by user: chmod 600 pkcs11_pin.conf
      4. Add content: RNS_PKCS11_PIN=123456

    Or use this function to create it safely:
      setup_config_file("my_app")

    Args:
        app_name: Unique app identifier

    Returns:
        True if hardware identity created/available, False otherwise.
    """
    print("\n" + "=" * 70)
    print("SETUP APPROACH 3: SECURE CONFIG FILE")
    print("=" * 70)

    print(f"\nSetting up hardware identity for: {app_name}")
    print()

    # Step 1: Locate or create config file
    print("Step 1: Setting up secure config file...")
    config_dir = Path.home() / ".config" / "reticulum"
    config_file = config_dir / "pkcs11_pin.conf"

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ Config directory ready: {config_dir}")

    except Exception as e:
        print(f"  ✗ Cannot create config dir: {e}")
        return False

    # Step 2: Check if config file exists
    if config_file.exists():
        print(f"  ✓ Config file exists: {config_file}")

        try:
            # Read PIN from config file
            with open(config_file, "r") as f:
                content = f.read().strip()

            if "RNS_PKCS11_PIN=" not in content:
                print(f"  ✗ Config file missing RNS_PKCS11_PIN entry")
                return False

            pin = content.split("=", 1)[1].strip()
            if not pin:
                print(f"  ✗ PIN in config file is empty")
                return False

            os.environ["RNS_PKCS11_PIN"] = pin
            print("  ✓ PIN loaded from config file")

        except Exception as e:
            print(f"  ✗ Error reading config: {e}")
            return False

    else:
        # Create new config file
        print(f"  Config file doesn't exist: {config_file}")
        print()
        print("  To create it:")
        print(f"    echo 'RNS_PKCS11_PIN=<your_pin>' > {config_file}")
        print(f"    chmod 600 {config_file}")
        print()
        print("  IMPORTANT: Set restrictive permissions (600) to protect the PIN!")
        print()
        return False

    # Step 3: Create hardware identity
    print(f"\nStep 2: Creating hardware identity for {app_name}...")
    try:
        hw_identity = create_app_hardware_identity(app_name, ensure_keys=True)

        if hw_identity is not None:
            print(f"  ✓ Hardware identity created successfully")
            print(f"    App: {app_name}")
            print(f"    Slot: {hw_identity.slot}")

            ed_pub, x_pub = hw_identity.get_public_keys()
            print(f"    Ed25519 public (first 16 bytes): {ed_pub[:16].hex()}")
            print(f"    X25519 public (first 16 bytes):  {x_pub[:16].hex()}")

            return True
        else:
            print(f"  ✗ Failed to create hardware identity")
            return False

    except PKCS11LoginError as e:
        print(f"  ✗ PIN incorrect: {e}")
        return False
    except PKCS11IdentityError as e:
        print(f"  ✗ Identity error: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False


# =============================================================================
# HELPER: Explicit Verification
# =============================================================================


def verify_hardware_identity(app_name: str) -> bool:
    """
    Verify that app's hardware identity is properly configured.

    Useful for diagnostics and health checks.

    Args:
        app_name: App identifier to verify

    Returns:
        True if valid hardware identity found, False otherwise.
    """
    print("\n" + "=" * 70)
    print("VERIFICATION: Check Hardware Identity Status")
    print("=" * 70)
    print()

    try:
        keys = get_app_identity_keys(app_name)

        if keys is None:
            print(f"  ✗ No hardware identity found for {app_name}")
            return False

        ed_pub, x_pub = keys

        print(f"  ✓ Hardware identity verified for {app_name}")
        print(f"    Ed25519 public key hash: {ed_pub[:16].hex()}...")
        print(f"    X25519 public key hash:  {x_pub[:16].hex()}...")

        return True

    except PKCS11IdentityError as e:
        print(f"  ✗ Verification failed: {e}")
        return False


# =============================================================================
# HELPER: Admin Diagnostics
# =============================================================================


def diagnose_setup() -> None:
    """
    Run diagnostics on the entire hardware identity setup.

    Useful for admins to troubleshoot issues.
    """
    print("\n" + "=" * 70)
    print("DIAGNOSTICS: Hardware Identity Setup")
    print("=" * 70)
    print()

    # Check environment
    print("1. Environment Variables:")
    print(f"   RNS_PKCS11_PIN set: {'Yes (not shown)' if os.environ.get('RNS_PKCS11_PIN') else 'No'}")
    print(f"   PKCS11_MODULE: {os.environ.get('PKCS11_MODULE', 'Not set (auto-discover)')}")
    print()

    # Check modules
    print("2. PKCS#11 Modules:")
    try:
        modules = discover_module_paths()
        if modules:
            for module in modules:
                print(f"   ✓ {module}")
        else:
            print("   ✗ No PKCS#11 modules found")
    except Exception as e:
        print(f"   ✗ Error discovering modules: {e}")
    print()

    # Check tokens
    print("3. Available Tokens:")
    try:
        modules = discover_module_paths()
        if modules:
            inventory = enumerate_token_inventory(module_paths=modules)
            if inventory:
                print(format_token_inventory(inventory))
            else:
                print("   ✗ No tokens found")
    except Exception as e:
        print(f"   ✗ Error enumerating tokens: {e}")
    print()

    # Check config
    print("4. App Configuration:")
    config_file = Path.home() / ".config" / "reticulum" / "pkcs11_app_slots.conf"
    if config_file.exists():
        print(f"   ✓ Config file exists: {config_file}")
        try:
            with open(config_file, "r") as f:
                content = f.read().strip()
            if content:
                for line in content.split("\n"):
                    if not line.startswith("#"):
                        print(f"     {line}")
        except Exception as e:
            print(f"   ✗ Error reading config: {e}")
    else:
        print(f"   ✗ No config file: {config_file}")
    print()


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main() -> int:
    """Run examples of all three setup approaches."""
    print()
    print("Reticulum Hardware Identity - Generic App Setup Examples")
    print("=" * 70)
    print()

    # Allow user to choose
    if len(sys.argv) > 1:
        approach = sys.argv[1].lower()
    else:
        print("Usage: python generic_app_setup.py <approach> [app_name]")
        print()
        print("Approaches:")
        print("  interactive    Interactive PIN entry at startup (for desktop apps)")
        print("  environment    PIN in RNS_PKCS11_PIN env var (for headless)")
        print("  config         PIN in secure config file (for daemons)")
        print("  verify         Verify existing hardware identity")
        print("  diagnose       Run diagnostics")
        print()
        print("Example:")
        print("  python generic_app_setup.py interactive sideband")
        print("  python generic_app_setup.py environment meshchat")
        print()
        return 1

    app_name = sys.argv[2] if len(sys.argv) > 2 else "test_app"

    # Run selected approach
    if approach == "interactive":
        success = setup_interactive(app_name)
    elif approach == "environment":
        success = setup_environment_variable(app_name)
    elif approach == "config":
        success = setup_config_file(app_name)
    elif approach == "verify":
        success = verify_hardware_identity(app_name)
    elif approach == "diagnose":
        diagnose_setup()
        return 0
    else:
        print(f"Unknown approach: {approach}")
        return 1

    if success:
        print("\n✓ Setup successful!")
        return 0
    else:
        print("\n✗ Setup failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

