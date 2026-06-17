"""
Example: How Sideband uses hardware-backed identity (zero changes to Sideband).

This example shows the pattern that Sideband (or any app) can use.
The key is: NO CHANGES NEEDED to the app's existing code.

Setup (one-time admin task):
  1. Install reticulum-pkcs11-identity: pip install reticulum-pkcs11-identity
  2. Configure PIN: export RNS_PKCS11_PIN=123456
  3. Done - apps will auto-detect and use hardware

Usage (in Sideband's identity initialization code):
  - Call get_or_create_hardware_identity("sideband")
  - If it returns an identity, use it; otherwise use software
  - Rest of code stays identical
"""

import RNS
from reticulum_pkcs11_identity import get_or_create_hardware_identity


def create_sideband_user_identity():
    """
    Create or retrieve Sideband's LXMF user identity.
    
    This is how Sideband's app would look with hardware support added.
    Note: Zero changes to Sideband's existing logic.
    """
    
    # Try hardware first (graceful fallback if unavailable)
    hw_identity = get_or_create_hardware_identity("sideband")
    
    if hw_identity:
        # Hardware identity is ready
        ed_public, x_public = hw_identity.get_public_keys()
        print(f"[Sideband] Using hardware identity on slot {hw_identity.slot}")
        
        # Create RNS.Identity with hardware-provided keys
        identity = create_rns_identity_from_keys(ed_public, x_public)
        
        # Override sign() and decrypt() to use hardware for signing/ECDH
        original_sign = identity.sign
        original_decrypt = identity.decrypt
        
        identity.sign = hw_identity.sign
        # For ECDH decryption, you'd need to integrate more deeply with RNS
        
        return identity
    else:
        # Hardware not available - use software identity as usual
        print("[Sideband] Hardware not available, using software identity")
        return create_software_identity()


def create_rns_identity_from_keys(ed_public: bytes, x_public: bytes) -> RNS.Identity:
    """
    Create RNS.Identity from hardware public keys.
    
    In real Sideband, this would integrate with RNS.Identity properly.
    This is just a placeholder showing the idea.
    """
    # Normally RNS.Identity.__init__ generates random software keys
    # Here we're providing hardware public keys instead
    
    identity = RNS.Identity(create_keys=False)
    
    # Set public keys from hardware
    # (Exact details depend on RNS.Identity's internal structure)
    identity.pub_bytes = x_public
    identity.sig_pub_bytes = ed_public
    
    # Initialize other RNS.Identity fields
    identity.update_hashes()
    
    return identity


def create_software_identity() -> RNS.Identity:
    """Fall back to standard software identity."""
    return RNS.Identity()


if __name__ == "__main__":
    # Example usage
    print("Sideband User Identity (with optional hardware backing)")
    print("=" * 60)
    
    identity = create_sideband_user_identity()
    print(f"Identity hash: {identity.hexhash}")
    print("Ready to use for LXMF messaging!")
