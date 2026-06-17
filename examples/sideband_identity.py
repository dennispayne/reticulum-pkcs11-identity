#!/usr/bin/env python3
"""
Example: Sideband with transparent hardware-backed identity support.

ZERO APP CHANGES PRINCIPLE:
  Sideband's identity initialization code needs just ONE addition:
  a call to get_or_create_hardware_identity("sideband"). Everything
  else stays identical.

Setup (one-time admin/developer task):
  1. Install: pip install reticulum-pkcs11-identity
  2. Configure PIN: export RNS_PKCS11_PIN=123456
     or: set RNS_PKCS11_PIN=123456  (Windows)
  3. Optional: export PKCS11_MODULE=/path/to/libsofthsm2.so
  4. Done - Sideband will auto-detect and use hardware

Usage (minimal change to Sideband):
  - Add: hw_identity = create_app_hardware_identity("sideband")
  - If hw_identity exists, use its sign() method for messages
  - Otherwise use software identity (existing code)
  - REST OF SIDEBAND CODE IS UNCHANGED

Benefits:
  - Private keys never leave the hardware token
  - Multi-app support (Meshchat, RNPhone, etc. can coexist)
  - Transparent fallback if hardware unavailable
  - Zero UI changes to Sideband
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


def create_sideband_user_identity() -> RNS.Identity | None:
    """
    Create or retrieve Sideband's LXMF user identity with optional hardware backing.

    This demonstrates the recommended pattern for Sideband (or any Reticulum app).
    Key principle: Zero changes to the app's existing identity creation logic.

    Returns:
        RNS.Identity if available (with hardware backing if configured),
        None if RNS unavailable.
    """
    if RNS is None:
        print("RNS not installed - skipping Sideband identity creation")
        return None

    try:
        # Step 1: Try to get hardware-backed identity
        hw_identity = create_app_hardware_identity("sideband", ensure_keys=True)

        if hw_identity is not None:
            # Step 2: Hardware is available - use it
            print(f"✓ [Sideband] Using hardware identity (slot {hw_identity.slot})")
            ed_public, x_public = hw_identity.get_public_keys()

            # Step 3: Create RNS.Identity from hardware public keys
            identity = _create_rns_identity_from_keys(ed_public, x_public)

            # Step 4: Replace signing with hardware-backed method
            # (In real Sideband, you'd integrate more deeply with RNS)
            original_sign = identity.sign
            identity.sign = lambda msg: hw_identity.sign(msg)

            print(f"   Identity hash: {identity.hexhash}")
            print("   Ready for LXMF messaging with hardware-backed signing!")
            return identity

    except PKCS11IdentityError as e:
        print(f"✗ [Sideband] Hardware identity error: {e}")
        print("   Falling back to software identity")

    # Step 5: Fall back to standard software identity
    print("✓ [Sideband] Using software identity")
    if RNS is not None:
        identity = RNS.Identity()
        print(f"   Identity hash: {identity.hexhash}")
        return identity

    return None


def query_sideband_hardware_setup() -> None:
    """
    Query Sideband's current hardware identity setup.

    Useful for diagnostics and admin tasks.
    """
    print("\n[Sideband] Hardware Identity Status")
    print("=" * 60)

    try:
        keys = get_app_identity_keys("sideband")
        if keys is not None:
            ed_pub, x_pub = keys
            print(f"  ✓ Hardware identity configured")
            print(f"    Ed25519 public key (first 16 bytes): {ed_pub[:16].hex()}")
            print(f"    X25519 public key (first 16 bytes):  {x_pub[:16].hex()}")
        else:
            print("  ✗ No hardware identity found for Sideband")
    except PKCS11IdentityError as e:
        print(f"  ✗ Error querying hardware identity: {e}")

    print()


def _create_rns_identity_from_keys(
    ed_public: bytes, x_public: bytes
) -> RNS.Identity:
    """
    Create RNS.Identity from hardware-provided public keys.

    Note: This is a simplified example. Real Sideband integration would
    need to work with RNS.Identity's internal structure more carefully.

    Args:
        ed_public: Ed25519 public key (32 bytes)
        x_public: X25519 public key (32 bytes)

    Returns:
        RNS.Identity configured with the provided keys.
    """
    if RNS is None:
        raise RuntimeError("RNS not installed")

    # Create identity without generating new keys
    identity = RNS.Identity(create_keys=False)

    # Set public key material from hardware
    identity.pub_bytes = x_public
    identity.sig_pub_bytes = ed_public

    # Recalculate derived hashes
    identity.update_hashes()

    return identity


def example_lxmf_messaging_with_hardware() -> None:
    """
    Example: How Sideband would use hardware identity for LXMF messaging.

    This shows the typical LXMF pattern with hardware-backed signing.
    """
    if RNS is None:
        print("RNS not installed - cannot demonstrate messaging")
        return

    print("\n[Sideband] Example: LXMF Messaging with Hardware Backing")
    print("=" * 60)

    try:
        identity = create_sideband_user_identity()
        if identity is None:
            print("No identity available")
            return

        # In real Sideband, this would be:
        #   - Create LXMF destination using the identity
        #   - Send messages (automatically signed by hardware if available)
        #   - Receive messages (verified with same public keys)

        test_message = b"Hello from Sideband with hardware backing!"

        # If hardware identity was used, this call goes to the token
        # Otherwise it uses software signing
        print(f"  Message to sign: {test_message}")
        print(f"  (Would be signed by {'hardware' if hasattr(identity.sign, '__self__') else 'software'})")

        print(f"  ✓ Ready for secure LXMF messaging")

    except Exception as e:
        print(f"  ✗ Error: {e}")

    print()


if __name__ == "__main__":
    print("Sideband Identity Example")
    print("=" * 60)
    print()

    # Example 1: Create/get identity
    identity = create_sideband_user_identity()

    # Example 2: Query setup
    query_sideband_hardware_setup()

    # Example 3: Show messaging pattern
    if identity is not None:
        example_lxmf_messaging_with_hardware()
    else:
        print("Cannot demonstrate messaging without identity")

    sys.exit(0)
