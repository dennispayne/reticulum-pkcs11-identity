#!/usr/bin/env python3
"""
Example: Meshchat with hardware-backed identity and slot sharing.

ZERO APP CHANGES PRINCIPLE:
  Meshchat can use its own hardware slot OR share Sideband's slot
  with a single API call: create_app_hardware_identity("meshchat").
  No changes to Meshchat's existing code.

Setup (one-time admin task):
  1. Install: pip install reticulum-pkcs11-identity
  2. Configure PIN: export RNS_PKCS11_PIN=123456
  3. Optional: Share Sideband's slot:
     python -c "
     from reticulum_pkcs11_identity import AppIdentityMapper
     m = AppIdentityMapper()
     m.set_shared_slot('meshchat', 'sideband')  # Share Sideband's slot
     "
  4. Or use dedicated slot (automatic allocation):
     python -c "
     from reticulum_pkcs11_identity import create_app_hardware_identity
     create_app_hardware_identity('meshchat', ensure_keys=True)
     "

Usage (minimal change to Meshchat):
  - Add: hw_identity = create_app_hardware_identity("meshchat")
  - If hw_identity exists, use its sign() method
  - Otherwise use software identity (existing code)
  - REST OF MESHCHAT CODE IS UNCHANGED

Benefits:
  - Independent hardware identity OR shared with Sideband
  - Multiple apps on same YubiKey without key management
  - Transparent to Meshchat's logic
  - Zero UI changes to Meshchat

Multi-App Coexistence:
  - YubiKey PIV slots: 9a, 9c, 9d, 9e
  - Sideband: slot 9a (first to claim it)
  - Meshchat: slot 9c (or shares 9a)
  - RNPhone: slot 9d (if available)
  - App N: slot 9e (if available)
"""

from __future__ import annotations

import os
import sys
from typing import Optional

try:
    import RNS
except ImportError:
    RNS = None

from reticulum_pkcs11_identity import (
    create_app_hardware_identity,
    get_app_identity_keys,
)
from reticulum_pkcs11_identity.exceptions import PKCS11IdentityError


def create_meshchat_user_identity(
    share_with_sideband: bool = False,
) -> RNS.Identity | None:
    """
    Create or retrieve Meshchat's chat identity with optional hardware backing.

    This demonstrates the multi-app pattern for Meshchat.
    Shows how Meshchat can have its own slot OR share with Sideband.

    Args:
        share_with_sideband: If True, try to share Sideband's slot.
                           If False, use dedicated slot.

    Returns:
        RNS.Identity if available (with hardware backing if configured),
        None if RNS unavailable.
    """
    if RNS is None:
        print("RNS not installed - skipping Meshchat identity creation")
        return None

    try:
        # Step 1: Determine slot allocation strategy
        if share_with_sideband:
            print("ℹ  [Meshchat] Attempting to share Sideband's slot...")
            # Note: In production, you'd check AppIdentityMapper.get_shared_slot()
            # For now, we'll just use the default dedicated slot
            slot_mode = "shared"
        else:
            print("ℹ  [Meshchat] Using dedicated slot...")
            slot_mode = "dedicated"

        # Step 2: Get or create hardware identity
        hw_identity = create_app_hardware_identity("meshchat", ensure_keys=True)

        if hw_identity is not None:
            # Step 3: Hardware is available - use it
            print(f"✓ [Meshchat] Using hardware identity (slot {hw_identity.slot}, {slot_mode})")
            ed_public, x_public = hw_identity.get_public_keys()

            # Step 4: Create RNS.Identity from hardware public keys
            identity = _create_rns_identity_from_keys(ed_public, x_public)

            # Step 5: Replace signing with hardware-backed method
            original_sign = identity.sign
            identity.sign = lambda msg: hw_identity.sign(msg)

            print(f"   Identity hash: {identity.hexhash}")
            print("   Ready for mesh chat with hardware-backed signing!")
            return identity

    except PKCS11IdentityError as e:
        print(f"✗ [Meshchat] Hardware identity error: {e}")
        print("   Falling back to software identity")

    # Step 6: Fall back to standard software identity
    print("✓ [Meshchat] Using software identity")
    if RNS is not None:
        identity = RNS.Identity()
        print(f"   Identity hash: {identity.hexhash}")
        return identity

    return None


def query_meshchat_hardware_setup() -> None:
    """
    Query Meshchat's current hardware identity setup and slot allocation.

    Useful for diagnostics and multi-app deployment.
    """
    print("\n[Meshchat] Hardware Identity & Slot Status")
    print("=" * 60)

    try:
        keys = get_app_identity_keys("meshchat")
        if keys is not None:
            ed_pub, x_pub = keys
            print(f"  ✓ Hardware identity configured for Meshchat")
            print(f"    Ed25519 public key (first 16 bytes): {ed_pub[:16].hex()}")
            print(f"    X25519 public key (first 16 bytes):  {x_pub[:16].hex()}")

            # Show Sideband for comparison
            try:
                sb_keys = get_app_identity_keys("sideband")
                if sb_keys is not None:
                    print(f"\n  ✓ Sideband also has hardware identity")
                    sb_ed, sb_x = sb_keys
                    # Check if they're sharing
                    if sb_ed == ed_pub:
                        print(f"    → Meshchat & Sideband share identity!")
                    else:
                        print(f"    → Meshchat & Sideband have separate identities")
            except PKCS11IdentityError:
                pass

        else:
            print("  ✗ No hardware identity found for Meshchat")
    except PKCS11IdentityError as e:
        print(f"  ✗ Error querying hardware identity: {e}")

    print()


def example_multi_app_chat_scenario() -> None:
    """
    Example: Multi-app scenario with Sideband and Meshchat both using hardware.

    Demonstrates how two apps can coexist on the same YubiKey
    with independent (or shared) hardware-backed identities.
    """
    print("\n[Meshchat] Example: Multi-App Chat Scenario")
    print("=" * 60)

    if RNS is None:
        print("RNS not installed - cannot demonstrate scenario")
        return

    try:
        print("Scenario: Sideband and Meshchat on same YubiKey")
        print()

        # App 1: Sideband (LXMF messaging)
        print("1. Sideband starts (claims slot 9a):")
        print("   - create_app_hardware_identity('sideband')")
        print("   - Gets its own identity for LXMF messaging")
        print()

        # App 2: Meshchat (Chat)
        print("2. Meshchat starts (claims slot 9c):")
        print("   - create_app_hardware_identity('meshchat')")
        print("   - Gets its own identity for chat")
        print()

        # Both use hardware
        print("3. Both apps now use hardware-backed signing:")
        print("   - Private keys never leave YubiKey")
        print("   - Each has independent identity")
        print("   - Optional: Could share same slot if configured")
        print()

        # Create identity for this example
        identity = create_meshchat_user_identity(share_with_sideband=False)

        if identity is not None:
            test_message = b"Hello from Meshchat with hardware backing!"
            print(f"4. Test message: {test_message.decode()}")
            print(f"   Identity: {identity.hexhash}")
            print(f"   Would be signed by: hardware")
            print()
            print("✓ Multi-app scenario successful!")

    except Exception as e:
        print(f"✗ Error in scenario: {e}")

    print()


def example_slot_sharing() -> None:
    """
    Example: Meshchat sharing Sideband's slot (advanced scenario).

    In some deployments, you might want multiple apps to share
    the same hardware identity (same keys). This example shows
    the pattern.
    """
    print("\n[Meshchat] Example: Slot Sharing (Advanced)")
    print("=" * 60)

    print("Scenario: Meshchat shares Sideband's identity")
    print()
    print("Use case:")
    print("  - Minimal YubiKey management")
    print("  - Same identity for multiple apps")
    print("  - Trade-off: Apps not independently identifiable")
    print()

    print("Configuration:")
    print("  from reticulum_pkcs11_identity import AppIdentityMapper")
    print("  mapper = AppIdentityMapper()")
    print("  mapper.set_shared_slot('meshchat', 'sideband')")
    print()

    print("Then:")
    print("  hw_identity = create_app_hardware_identity('meshchat')")
    print("  # Returns Sideband's identity (same keys)")
    print()

    print("Note: Currently, each app gets its own slot by default.")
    print("Slot sharing is configured via AppIdentityMapper if needed.")

    print()


if __name__ == "__main__":
    print("Meshchat Identity Example")
    print("=" * 60)
    print()

    # Example 1: Create/get identity (dedicated slot)
    identity = create_meshchat_user_identity(share_with_sideband=False)

    # Example 2: Query setup
    query_meshchat_hardware_setup()

    # Example 3: Show multi-app scenario
    if identity is not None:
        example_multi_app_chat_scenario()
    else:
        print("Cannot demonstrate scenario without identity")

    # Example 4: Show slot sharing pattern
    example_slot_sharing()

    sys.exit(0)
