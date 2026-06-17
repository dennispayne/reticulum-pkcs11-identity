"""
Tests for transparent RNS.Identity integration.
"""

import os
import pytest

from reticulum_pkcs11_identity.rns_integration import (
    _detect_app_name,
    _get_hardware_keys_for_app,
    enable_hardware_identity_injection,
    is_identity_hardware_backed,
    get_identity_app_name,
    get_identity_slot,
)


class TestAppDetection:
    """Test app name detection."""

    def test_detect_app_from_env_var(self):
        """Test app detection from environment variable."""
        os.environ["RNS_APP_NAME"] = "test_app"
        try:
            app_name = _detect_app_name()
            assert app_name == "test_app"
        finally:
            del os.environ["RNS_APP_NAME"]

    def test_detect_app_from_module_name(self):
        """Test app detection from calling module."""
        # This test just verifies the function doesn't crash
        app_name = _detect_app_name()
        # May be None or some module name - that's OK
        assert app_name is None or isinstance(app_name, str)


class TestHardwareKeyRetrieval:
    """Test hardware key retrieval for apps."""

    def test_get_hardware_keys_unknown_app(self):
        """Test getting keys for unknown app."""
        # Unknown app with no mapping
        keys = _get_hardware_keys_for_app("unknown_app_xyz")
        assert keys is None

    def test_get_hardware_keys_no_session(self):
        """Test key retrieval when session not initialized."""
        # No session running
        from reticulum_pkcs11_identity.session_manager import shutdown_session
        shutdown_session()
        
        keys = _get_hardware_keys_for_app("any_app")
        assert keys is None


class TestIdentityIntrospection:
    """Test hardware identity detection."""

    def test_is_identity_hardware_backed_default(self):
        """Test identity is not hardware-backed by default."""
        class FakeIdentity:
            pass
        
        fake = FakeIdentity()
        assert not is_identity_hardware_backed(fake)

    def test_get_identity_app_name_none_by_default(self):
        """Test app name is None for non-hardware identity."""
        class FakeIdentity:
            pass
        
        fake = FakeIdentity()
        assert get_identity_app_name(fake) is None

    def test_get_identity_slot_none_by_default(self):
        """Test slot is None for non-hardware identity."""
        class FakeIdentity:
            pass
        
        fake = FakeIdentity()
        assert get_identity_slot(fake) is None


class TestMonkeyPatch:
    """Test monkey patching setup."""

    def test_enable_injection_without_rns(self):
        """Test that enabling injection without RNS doesn't crash."""
        # Hide RNS temporarily
        import sys
        rns_backup = sys.modules.get("RNS")
        if "RNS" in sys.modules:
            del sys.modules["RNS"]
        
        try:
            # Should not crash
            enable_hardware_identity_injection()
        finally:
            # Restore
            if rns_backup:
                sys.modules["RNS"] = rns_backup


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
