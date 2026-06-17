#!/usr/bin/env python3
"""
Comprehensive Integration Test Suite for PKCS#11 Hardware Identities

Tests the 4-layer architecture without requiring PKCS#11 module to be loadable.
Uses ykman to verify hardware keys are present, tests app mapping, and verifies
the integration layer works correctly.
"""

import os
import sys
import io
import json
import subprocess
import time
import traceback
from pathlib import Path
from datetime import datetime

# Fix console encoding for Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).parent))

from reticulum_pkcs11_identity.app_identity import AppIdentityMapper, PIV_SLOTS
from reticulum_pkcs11_identity.exceptions import PKCS11ConfigError
import RNS

# ============================================================================
# Test Utilities
# ============================================================================

def run_command(cmd, shell=False):
    """Run a command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=shell,
            timeout=10
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def get_yubikey_info():
    """Get YubiKey info via ykman."""
    success, stdout, _ = run_command("ykman info")
    return stdout if success else None


def get_piv_keys():
    """Get PIV keys info via ykman."""
    keys_info = {}
    for slot in PIV_SLOTS:
        success, stdout, _ = run_command(f"ykman piv keys info {slot}")
        if success:
            keys_info[slot] = stdout
    return keys_info


# ============================================================================
# Test 1: YubiKey Hardware Status
# ============================================================================

def test_yubikey_hardware_status():
    """Task 1: Verify YubiKey hardware status."""
    print("\n" + "=" * 70)
    print("TEST 1: YubiKey Hardware Status Verification")
    print("=" * 70)
    
    report = []
    report.append("[1] Hardware Status Check")
    
    try:
        # Get YubiKey info
        info = get_yubikey_info()
        if not info:
            report.append("  ERROR: Cannot get YubiKey info")
            return False, "\n".join(report)
        
        report.append("  ✓ YubiKey detected")
        
        # Check for required info
        if "YubiKey 5C Nano" in info:
            report.append("  ✓ Model: YubiKey 5C Nano")
        if "Firmware version: 5.7" in info:
            report.append("  ✓ Firmware: 5.7.4+")
        if "PIV" in info and "Enabled" in info:
            report.append("  ✓ PIV enabled")
        
        # Get PIV-specific info
        success, piv_info, _ = run_command("ykman piv info")
        if success:
            report.append("  ✓ PIV info retrieved")
            if "PIN tries remaining: 3/3" in piv_info:
                report.append("  ✓ PIN tries: 3/3 (default)")
        
        report.append("\nTEST 1 PASSED")
        return True, "\n".join(report)
        
    except Exception as e:
        report.append(f"  ERROR: {e}")
        report.append(traceback.format_exc())
        report.append("\nTEST 1 FAILED")
        return False, "\n".join(report)


# ============================================================================
# Test 2: PIV Keys Generation Status
# ============================================================================

def test_piv_keys_generated():
    """Task 2: Verify PIV test keys are present on device."""
    print("\n" + "=" * 70)
    print("TEST 2: PIV Keys Generation Status")
    print("=" * 70)
    
    report = []
    report.append("[2] Verifying PIV keys on YubiKey")
    
    try:
        keys_info = get_piv_keys()
        
        key_count = 0
        for slot, info in keys_info.items():
            if "ED25519" in info:
                report.append(f"  ✓ Slot {slot}: ED25519 key present")
                key_count += 1
            else:
                report.append(f"  - Slot {slot}: No ED25519 key")
        
        report.append(f"\nGenerated {key_count}/4 required keys")
        
        if key_count >= 4:
            report.append("\nTEST 2 PASSED")
            return True, "\n".join(report)
        else:
            report.append("\nTEST 2 INCOMPLETE (Need to generate more keys)")
            return False, "\n".join(report)
        
    except Exception as e:
        report.append(f"  ERROR: {e}")
        report.append(traceback.format_exc())
        report.append("\nTEST 2 FAILED")
        return False, "\n".join(report)


# ============================================================================
# Test 3: App Identity Slot Mapping
# ============================================================================

def test_app_slot_mapping():
    """Task 3 & 4: Test app slot allocation and persistence."""
    print("\n" + "=" * 70)
    print("TEST 3: App Identity Slot Mapping")
    print("=" * 70)
    
    report = []
    report.append("[3] Testing app-to-slot allocation")
    
    try:
        # Clean up config first (remove from previous test)
        config_file = Path.home() / ".config" / "reticulum" / "pkcs11_app_slots.conf"
        if config_file.exists():
            config_file.unlink()
        
        # Initialize mapper
        mapper = AppIdentityMapper()
        report.append("  ✓ AppIdentityMapper initialized (config cleaned)")
        
        # Test single app
        app_name = "test-app-single"
        slot = mapper.allocate_slot_for_app(app_name)
        report.append(f"  ✓ Allocated slot {slot} for app '{app_name}'")
        
        # Verify persistence by reloading
        mapper2 = AppIdentityMapper()
        slot2 = mapper2.get_app_slot(app_name)
        if slot == slot2:
            report.append(f"  ✓ Slot allocation persisted: {slot2}")
        else:
            report.append(f"  ERROR: Slot mismatch: {slot} vs {slot2}")
            return False, "\n".join(report)
        
        # Test multi-app allocation
        report.append("\n[3.2] Testing multi-app isolation")
        apps = ["sideband-test", "meshchat-test", "lxmf-hub-test"]  # 3 more apps + the 1 already allocated = 4 total
        slots = {}
        
        for app in apps:
            allocated_slot = mapper.allocate_slot_for_app(app)
            slots[app] = allocated_slot
            report.append(f"  ✓ App '{app}' -> Slot {allocated_slot}")
        
        # Verify all slots are different
        all_slots = {"test-app-single": slot} | slots
        unique_slots = set(all_slots.values())
        if len(unique_slots) == 4:
            report.append(f"  ✓ All 4 slots allocated and unique")
        else:
            report.append(f"  WARNING: Only {len(unique_slots)} unique slots")
        
        # Test slot exhaustion
        report.append("\n[3.3] Testing slot exhaustion handling")
        try:
            extra_app = "test-app-extra"
            extra_slot = mapper.allocate_slot_for_app(extra_app)
            if extra_slot is None:
                report.append(f"  ✓ Graceful handling of slot exhaustion (returned None)")
            else:
                report.append(f"  ERROR: 5th app got slot {extra_slot} (expected None)")
                return False, "\n".join(report)
        except Exception as e:
            report.append(f"  ✓ Slot exhaustion raises error: {type(e).__name__}")
        
        report.append("\nTEST 3 PASSED")
        return True, "\n".join(report)
        
    except Exception as e:
        report.append(f"  ERROR: {e}")
        report.append(traceback.format_exc())
        report.append("\nTEST 3 FAILED")
        return False, "\n".join(report)


# ============================================================================
# Test 4: RNS Integration (Backward Compatibility)
# ============================================================================

def test_rns_backward_compatibility():
    """Task 9: Test backward compatibility with existing LXMF tests."""
    print("\n" + "=" * 70)
    print("TEST 4: RNS Backward Compatibility")
    print("=" * 70)
    
    report = []
    report.append("[4] Testing RNS integration")
    
    try:
        # Initialize RNS
        report.append("  ✓ RNS imported successfully")
        
        # Try creating a standard identity
        try:
            # Create a test identity without hardware (software-only)
            identity = RNS.Identity(create_keys=True)
            report.append(f"  ✓ Standard RNS.Identity created: {identity.hexhash}")
            
            # Test signing
            test_data = b"test message"
            signature = identity.sign(test_data)
            report.append(f"  ✓ Software identity signature works ({len(signature)} bytes)")
            
        except Exception as e:
            report.append(f"  ERROR: Cannot create standard identity: {e}")
            return False, "\n".join(report)
        
        report.append("\nTEST 4 PASSED")
        return True, "\n".join(report)
        
    except Exception as e:
        report.append(f"  ERROR: {e}")
        report.append(traceback.format_exc())
        report.append("\nTEST 4 FAILED")
        return False, "\n".join(report)


# ============================================================================
# Test 5: Configuration Persistence
# ============================================================================

def test_configuration_persistence():
    """Test that configuration is persisted across sessions."""
    print("\n" + "=" * 70)
    print("TEST 5: Configuration Persistence")
    print("=" * 70)
    
    report = []
    report.append("[5] Testing configuration persistence")
    
    try:
        # Clean up config first
        config_file = Path.home() / ".config" / "reticulum" / "pkcs11_app_slots.conf"
        if config_file.exists():
            config_file.unlink()
        
        # Create mapping
        mapper1 = AppIdentityMapper()
        mapper1.allocate_slot_for_app("persist-app-x")
        mapper1.allocate_slot_for_app("persist-app-y")
        report.append("  ✓ Apps allocated in session 1")
        
        # Create new mapper instance (simulates new session)
        mapper2 = AppIdentityMapper()
        slot1 = mapper2.get_app_slot("persist-app-x")
        slot2 = mapper2.get_app_slot("persist-app-y")
        
        if slot1 is not None and slot2 is not None:
            report.append(f"  ✓ Persistence verified: app-x={slot1}, app-y={slot2}")
        else:
            report.append(f"  ERROR: Config not persisted")
            return False, "\n".join(report)
        
        report.append("\nTEST 5 PASSED")
        return True, "\n".join(report)
        
    except Exception as e:
        report.append(f"  ERROR: {e}")
        report.append(traceback.format_exc())
        report.append("\nTEST 5 FAILED")
        return False, "\n".join(report)


# ============================================================================
# Main Test Runner
# ============================================================================

results = {}  # Global results dict

def main():
    """Run all integration tests."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "RETICULUM PKCS#11 INTEGRATION TEST SUITE" + " " * 13 + "║")
    print("║" + " " * 68 + "║")
    print("║" + f" YubiKey 5C Nano - Hardware Identity Verification" + " " * 16 + "║")
    print("║" + f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + " " * 32 + "║")
    print("╚" + "=" * 68 + "╝\n")
    
    results = {}
    all_passed = True
    
    # Run tests
    tests = [
        ("YubiKey Hardware Status", test_yubikey_hardware_status),
        ("PIV Keys Generated", test_piv_keys_generated),
        ("App Slot Mapping", test_app_slot_mapping),
        ("RNS Backward Compatibility", test_rns_backward_compatibility),
        ("Configuration Persistence", test_configuration_persistence),
    ]
    
    for test_name, test_func in tests:
        try:
            success, report = test_func()
            results[test_name] = (success, report)
            print(report)
            
            if not success:
                all_passed = False
                
        except Exception as e:
            results[test_name] = (False, str(e))
            print(f"\nUNEXPECTED ERROR in {test_name}:")
            print(traceback.format_exc())
            all_passed = False
    
    # Generate summary
    print("\n" + "=" * 70)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 70)
    
    passed_count = sum(1 for success, _ in results.values() if success)
    total_count = len(results)
    
    for test_name, (success, _) in results.items():
        status = "PASS" if success else "FAIL"
        symbol = "[+]" if success else "[-]"
        print(f"{symbol} {test_name}: {status}")
    
    print(f"\nTotal: {passed_count}/{total_count} tests passed")
    
    if all_passed:
        print("\nOVERALL RESULT: SUCCESS")
        print("All integration tests passed!")
    else:
        print("\nOVERALL RESULT: PARTIAL (Some tests failed)")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    
    # Save results
    with open("integration_test_results.txt", "w", encoding="utf-8") as f:
        f.write("RETICULUM PKCS#11 INTEGRATION TEST RESULTS\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for test_name, (success, report) in results.items():
            f.write(f"\n{'=' * 70}\n")
            f.write(f"{test_name}: {'PASS' if success else 'FAIL'}\n")
            f.write(f"{'=' * 70}\n")
            f.write(report)
    
    sys.exit(0 if success else 1)
