"""
Tests for PKCS#11 configuration management.
"""

import os
import tempfile
import pytest

from reticulum_pkcs11_identity.config import PKCS11Config, ConfigBuilder
from reticulum_pkcs11_identity.exceptions import PKCS11ConfigError


class TestPKCS11Config:
    """Test configuration management."""

    def test_config_defaults(self):
        """Test config defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            
            assert config.get_provider() == "auto"
            assert config.get_token_label() is None
            assert config.get_pin_env_var() == "RNS_PKCS11_PIN"

    def test_config_save_and_load(self):
        """Test config persistence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            
            # Write config
            config1 = PKCS11Config(config_file)
            config1.set_provider("/usr/lib/libykcs11.so")
            config1.set_token_label("YubiKey PIV #12345")
            config1.set_pin("123456", save=True)
            
            # Read config
            config2 = PKCS11Config(config_file)
            assert config2.get_provider() == "/usr/lib/libykcs11.so"
            assert config2.get_token_label() == "YubiKey PIV #12345"
            assert config2.get_pin() == "123456"

    def test_config_pin_from_env(self):
        """Test PIN retrieval from environment variable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            
            # Set env var
            os.environ["RNS_PKCS11_PIN"] = "env_pin_123"
            try:
                # Should get PIN from env
                assert config.get_pin() == "env_pin_123"
            finally:
                del os.environ["RNS_PKCS11_PIN"]

    def test_config_pin_priority(self):
        """Test PIN priority: file > env var."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            
            # Set env var
            os.environ["RNS_PKCS11_PIN"] = "env_pin"
            try:
                # Set file PIN (should take priority)
                config.set_pin("file_pin", save=True)
                assert config.get_pin() == "file_pin"
            finally:
                del os.environ["RNS_PKCS11_PIN"]

    def test_config_custom_pin_env_var(self):
        """Test custom PIN environment variable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            
            # Set custom env var
            config.set_pin_env_var("MY_CUSTOM_PIN_VAR")
            os.environ["MY_CUSTOM_PIN_VAR"] = "custom_pin_value"
            try:
                assert config.get_pin() == "custom_pin_value"
            finally:
                del os.environ["MY_CUSTOM_PIN_VAR"]

    def test_config_validate_missing_pin(self):
        """Test validation fails with missing PIN."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            
            # No PIN set
            with pytest.raises(PKCS11ConfigError):
                config.validate()

    def test_config_validate_success(self):
        """Test validation succeeds with PIN."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            config.set_pin("123456", save=True)
            
            # Should not raise
            config.validate()

    def test_config_builder(self):
        """Test ConfigBuilder fluent API."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            
            config = (
                ConfigBuilder()
                .with_provider("/usr/lib/libykcs11.so")
                .with_token_label("YubiKey PIV #99999")
                .with_pin("builder_pin", save=True)
                .build()
            )
            
            # Verify via file reload
            config2 = PKCS11Config(config_file)
            # Note: Builder doesn't use same config_file, so this just tests fluent API
            assert config.get_provider() == "/usr/lib/libykcs11.so"
            assert config.get_token_label() == "YubiKey PIV #99999"

    def test_config_repr(self):
        """Test string representation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            config.set_pin("secret_pin", save=True)
            
            repr_str = repr(config)
            assert "PKCS11Config" in repr_str
            assert "***" in repr_str  # PIN should be masked


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
