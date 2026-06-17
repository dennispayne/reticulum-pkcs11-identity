"""
Tests for transparent RNS.Identity integration.
"""

import os
import pytest
import tempfile
from unittest.mock import Mock, patch

from reticulum_pkcs11_identity.rns_integration import (
    _detect_app_name,
    _get_hardware_keys_for_app,
    enable_hardware_identity_injection,
    is_identity_hardware_backed,
    get_identity_app_name,
    get_identity_slot,
    _auto_initialize,
    _install_monkey_patch,
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
        # Unknown app with no mapping and no backend
        keys = _get_hardware_keys_for_app("unknown_app_xyz", backend=None)
        assert keys is None

    def test_get_hardware_keys_no_backend(self):
        """Test key retrieval without backend returns None."""
        # No backend provided
        keys = _get_hardware_keys_for_app("any_app", backend=None)
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


class TestAutoInitialization:
    """Test auto-initialization at module import."""

    def test_auto_initialize_disabled_config(self):
        """Test auto-initialization with disabled config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config")
            
            # Create a config file with disabled hardware identity
            with open(config_path, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("enabled = false\n")
            
            # Mock config loading
            with patch("reticulum_pkcs11_identity.rns_integration.load_hardware_identity_config") as mock_load_config:
                mock_load_config.return_value = {
                    "enabled": False,
                    "provider": None,
                    "token_label": None,
                    "exclude_apps": [],
                    "detected_providers": {}
                }
                
                # Call auto-init
                _auto_initialize()
                
                # Should have called config loading
                mock_load_config.assert_called_once()

    def test_auto_initialize_with_excluded_app(self):
        """Test auto-initialization skips excluded apps."""
        with patch("reticulum_pkcs11_identity.rns_integration.load_hardware_identity_config") as mock_load_config:
            with patch("reticulum_pkcs11_identity.rns_integration._detect_app_name") as mock_detect_app:
                mock_load_config.return_value = {
                    "enabled": True,
                    "provider": None,
                    "token_label": None,
                    "exclude_apps": ["myapp"],
                    "detected_providers": {}
                }
                mock_detect_app.return_value = "myapp"
                
                # Call auto-init
                _auto_initialize()
                
                # Should have loaded config and detected app
                mock_load_config.assert_called_once()
                mock_detect_app.assert_called_once()

    def test_auto_initialize_no_provider(self):
        """Test auto-initialization with no provider available."""
        with patch("reticulum_pkcs11_identity.rns_integration.load_hardware_identity_config") as mock_load_config:
            mock_load_config.return_value = {
                "enabled": True,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            # Call auto-init - should warn but not crash
            _auto_initialize()
            
            # Should have called config loading
            mock_load_config.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
