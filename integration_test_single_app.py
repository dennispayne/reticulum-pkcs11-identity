#!/usr/bin/env python3
"""
Integration Test 1: Single-App Hardware Identity
Tests that a single application can create a hardware-backed identity on YubiKey.
"""

import os
import sys
import io
import time
import traceback
from pathlib import Path

# Fix console encoding for Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure we import from the local project
sys.path.insert(0, str(Path(__file__).parent))

from reticulum_pkcs11_identity.backend import PKCS11Backend
from reticulum_pkcs11_identity.app_identity import AppIdentityMapper
from reticulum_pkcs11_identity.identity import make_app_hardware_identity_class, create_app_hardware_identity
from reticulum_pkcs11_identity.exceptions import PKCS11BackendError, PKCS11KeyNotFoundError
from reticulum_pkcs11_identity.discovery import discover_module_paths
import RNS

def main():
    """Test single-app hardware identity creation and signing."""
    report = []
    backend = None
    
    try:
        report.append("=" * 70)
        report.append("INTEGRATION TEST 1: Single-App Hardware Identity")
        report.append("=" * 70)
        report.append("")
        
        # Setup
        report.append("[SETUP] Initializing...")
        os.environ["RNS_PKCS11_PIN"] = "123456"
        
        # Discover PKCS#11 modules
        modules = discover_module_paths()
        report.append(f"  - Found {len(modules)} PKCS#11 modules")
        if not modules:
            report.append("  - ERROR: No PKCS#11 modules found!")
            raise PKCS11BackendError("No PKCS#11 modules available")
        
        # Initialize backend with YubiKey
        backend = PKCS11Backend(
            module_path=modules[0],
            token_label="YubiKey PIV",  # Standard YubiKey label
            slot_id=None
        )
        report.append("  - Backend initialized")
        report.append(f"  - Module: {modules[0]}")
        
        # Open session with YubiKey
        try:
            backend.open_session(pin="123456")
            report.append("  - Session opened with PIN 123456")
        except Exception as e:
            report.append(f"  - ERROR opening session: {e}")
            raise
        
        # Setup app mapping
        mapper = AppIdentityMapper()
        report.append("  - App mapper initialized")
        
        # Allocate slot for test app
        app_name = "test-sideband"
        slot = mapper.allocate_slot_for_app(app_name)
        report.append(f"  - Allocated slot {slot} for app '{app_name}'")
        
        # Ensure keys exist on device
        report.append("")
        report.append("[KEYGEN] Generating/ensuring keys on YubiKey...")
        sign_key_label = f"{app_name}-sign"
        enc_key_label = f"{app_name}-enc"
        
        try:
            # Try to retrieve existing keys
            ed_pub = backend.get_public_key_bytes(key_label=sign_key_label)
            x_pub = backend.get_public_key_bytes(key_label=enc_key_label)
            report.append(f"  - Ed25519 key label: {sign_key_label}")
            report.append(f"  - Ed25519 public key: {ed_pub.hex()[:32]}...")
            report.append(f"  - X25519 key label: {enc_key_label}")
            report.append(f"  - X25519 public key: {x_pub.hex()[:32]}...")
        except PKCS11KeyNotFoundError:
            report.append("  - Keys not found, generating...")
            ed_pub = backend.generate_ed25519_keypair(label=sign_key_label)
            x_pub = backend.generate_x25519_keypair(label=enc_key_label)
            report.append(f"  - Generated Ed25519 key: {ed_pub.hex()[:32]}...")
            report.append(f"  - Generated X25519 key: {x_pub.hex()[:32]}...")
        
        # Create hardware identity
        report.append("")
        report.append("[IDENTITY] Creating hardware-backed identity...")
        start_time = time.time()
        
        try:
            IdentityClass = make_app_hardware_identity_class(
                app_name=app_name,
                backend=backend,
                slot=slot
            )
            identity = IdentityClass(create_keys=True)
            elapsed = time.time() - start_time
            report.append(f"  - Identity created successfully ({elapsed:.2f}s)")
            report.append(f"  - Identity hash: {identity.hexhash}")
        except Exception as e:
            report.append(f"  - ERROR creating identity: {e}")
            raise
        
        # Verify keys
        report.append("")
        report.append("[VERIFY] Verifying identity keys...")
        pub_key = identity.get_public_key()
        report.append(f"  - Public key: {pub_key.hex()[:32]}...")
        report.append(f"  - Public key length: {len(pub_key)} bytes")
        
        # Sign test data
        report.append("")
        report.append("[SIGNING] Testing hardware signature...")
        test_data = b"test message for integration test"
        start_time = time.time()
        signature = identity.sign(test_data)
        elapsed = time.time() - start_time
        
        if signature is None or len(signature) == 0:
            report.append("  - ERROR: Signature is empty")
            raise PKCS11BackendError("Signature failed")
        
        report.append(f"  - Signature created successfully ({elapsed:.2f}s)")
        report.append(f"  - Signature length: {len(signature)} bytes")
        report.append(f"  - Signature: {signature.hex()[:32]}...")
        
        # Verify signature
        report.append("")
        report.append("[VERIFY SIGNATURE] Verifying signature...")
        try:
            # RNS Identity.verify() expects the public key to verify
            # We'll verify using the identity's public key directly
            from RNS.Cryptography import Ed25519PublicKey
            
            pub = Ed25519PublicKey(pub_key)
            pub.verify(signature, test_data)
            report.append("  - Signature verified successfully!")
        except Exception as e:
            report.append(f"  - ERROR: Signature verification failed: {e}")
            raise
        
        # Success
        report.append("")
        report.append("=" * 70)
        report.append("TEST PASSED: Single-app hardware identity works!")
        report.append("=" * 70)
        report.append("")
        
        return True, "\n".join(report)
        
    except Exception as e:
        report.append("")
        report.append("=" * 70)
        report.append("TEST FAILED")
        report.append("=" * 70)
        report.append(f"Error: {e}")
        report.append("")
        report.append("Traceback:")
        report.append(traceback.format_exc())
        
        return False, "\n".join(report)
    
    finally:
        # Cleanup
        try:
            if backend is not None:
                backend.close()
        except:
            pass

if __name__ == "__main__":
    success, output = main()
    
    # Print and save report
    print(output, file=sys.stdout)
    sys.stdout.flush()
    
    with open("integration_test_single_app.txt", "w", encoding="utf-8") as f:
        f.write(output)
    
    sys.exit(0 if success else 1)
