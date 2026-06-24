"""
Tests for PKCS#11 configuration management.
"""

import os
import tempfile
import pytest

from reticulum_pkcs11_identity.config import (
    PKCS11Config,
    ConfigBuilder,
    load_hardware_identity_config,
    multi_identity_enabled,
)
from reticulum_pkcs11_identity.exceptions import PKCS11ConfigError


class TestExperimentalFlags:
    """Config-driven gate for the experimental multi-identity feature."""

    def _write_config(self, tmpdir, body):
        path = os.path.join(tmpdir, "config")
        with open(path, "w") as fh:
            fh.write(body)
        return path

    def test_flags_default_off(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_config(tmpdir, "[hardware_identity]\nenabled = true\n")
            cfg = load_hardware_identity_config(path)
            assert cfg["experimental_features"] is False
            assert cfg["multi_identity"] is False
            assert multi_identity_enabled(cfg) is False

    def test_both_flags_enable_feature(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_config(
                tmpdir,
                "[hardware_identity]\nexperimental_features = on\nmulti_identity = on\n",
            )
            cfg = load_hardware_identity_config(path)
            assert cfg["experimental_features"] is True
            assert cfg["multi_identity"] is True
            assert multi_identity_enabled(cfg) is True

    def test_master_switch_required(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_config(tmpdir, "[hardware_identity]\nmulti_identity = on\n")
            cfg = load_hardware_identity_config(path)
            # multi_identity alone is not enough without experimental_features.
            assert multi_identity_enabled(cfg) is False

    def test_feature_flag_required(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_config(tmpdir, "[hardware_identity]\nexperimental_features = on\n")
            cfg = load_hardware_identity_config(path)
            assert multi_identity_enabled(cfg) is False

    def test_missing_or_empty_config_is_disabled(self):
        assert multi_identity_enabled({}) is False


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
        """Provider/token persist, but the PIN is never written to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            
            # Write config
            config1 = PKCS11Config(config_file)
            config1.set_provider("/usr/lib/libykcs11.so")
            config1.set_token_label("YubiKey PIV #12345")
            config1.set_pin("123456")
            
            # Read config
            config2 = PKCS11Config(config_file)
            assert config2.get_provider() == "/usr/lib/libykcs11.so"
            assert config2.get_token_label() == "YubiKey PIV #12345"
            # The PIN must never have been persisted to disk.
            assert config2.get_pin() is None
            with open(config_file) as fh:
                assert "123456" not in fh.read()

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
        """An in-memory PIN takes priority over the env var (and is not saved)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            
            # Set env var
            os.environ["RNS_PKCS11_PIN"] = "env_pin"
            try:
                # An in-memory PIN (this process only) takes priority.
                config.set_pin("mem_pin")
                assert config.get_pin() == "mem_pin"
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

    def test_config_validate_no_pin_required(self):
        """Validation no longer requires a stored PIN (it is prompted at runtime)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            
            # No PIN set: validation still passes (provider defaults to "auto").
            config.validate()

            # But a missing provider still fails.
            config.set_provider("")
            with pytest.raises(PKCS11ConfigError):
                config.validate()

    def test_config_validate_success(self):
        """Validation succeeds when a provider is configured."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            config = PKCS11Config(config_file)
            config.set_provider("/usr/lib/libykcs11.so")
            
            # Should not raise (no PIN required).
            config.validate()

    def test_config_pin_in_file_is_ignored(self):
        """A PIN manually written into the config file is ignored on load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            with open(config_file, "w") as fh:
                fh.write('provider = "/usr/lib/libykcs11.so"\n')
                fh.write('pin = "123456"\n')

            config = PKCS11Config(config_file)
            assert config.get_provider() == "/usr/lib/libykcs11.so"
            assert config.get_pin() is None

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


class TestHardwareIdentityConfig:
    """Test hardware_identity section parsing."""

    def test_hardware_identity_config_not_found(self):
        """Test graceful handling when config file not found."""
        config = load_hardware_identity_config("/nonexistent/config")
        
        assert config["enabled"] is False
        assert config["provider"] is None
        assert config["token_label"] is None
        assert config["exclude_apps"] == []
        assert config["detected_providers"] == {}

    def test_hardware_identity_config_no_section(self):
        """Test when Reticulum config exists but no [hardware_identity] section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            # Write a Reticulum config without [hardware_identity] section
            with open(config_file, "w") as f:
                f.write("[interface_default]\n")
                f.write("enabled = true\n")
            
            config = load_hardware_identity_config(config_file)
            
            assert config["enabled"] is False
            assert config["provider"] is None
            assert config["exclude_apps"] == []

    def test_hardware_identity_config_enabled(self):
        """Test parsing enabled flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("enabled = true\n")
            
            config = load_hardware_identity_config(config_file)
            assert config["enabled"] is True

    def test_hardware_identity_config_enabled_variants(self):
        """Test various boolean representations for enabled."""
        variants = [
            ("true", True),
            ("yes", True),
            ("1", True),
            ("on", True),
            ("false", False),
            ("no", False),
            ("0", False),
            ("off", False),
        ]
        
        for variant, expected in variants:
            with tempfile.TemporaryDirectory() as tmpdir:
                config_file = os.path.join(tmpdir, "config")
                
                with open(config_file, "w") as f:
                    f.write("[hardware_identity]\n")
                    f.write(f"enabled = {variant}\n")
                
                config = load_hardware_identity_config(config_file)
                assert config["enabled"] is expected, f"Failed for variant: {variant}"

    def test_hardware_identity_config_provider(self):
        """Test parsing provider setting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("provider = libykcs11\n")
            
            config = load_hardware_identity_config(config_file)
            assert config["provider"] == "libykcs11"

    def test_hardware_identity_config_provider_path(self):
        """Test parsing provider as file path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            # Create a dummy provider file
            provider_path = os.path.join(tmpdir, "libykcs11.so")
            with open(provider_path, "w") as f:
                f.write("dummy")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write(f"provider = {provider_path}\n")
            
            config = load_hardware_identity_config(config_file)
            assert config["provider"] == provider_path

    def test_hardware_identity_config_token_label(self):
        """Test parsing token_label setting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("token_label = YubiKey PIV #12345\n")
            
            config = load_hardware_identity_config(config_file)
            assert config["token_label"] == "YubiKey PIV #12345"

    def test_hardware_identity_config_exclude_apps_comma_separated(self):
        """Test parsing exclude_apps as comma-separated list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("exclude_apps = app1, app2, app3\n")
            
            config = load_hardware_identity_config(config_file)
            assert config["exclude_apps"] == ["app1", "app2", "app3"]

    def test_hardware_identity_config_exclude_apps_single(self):
        """Test parsing exclude_apps with single entry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("exclude_apps = debug_app\n")
            
            config = load_hardware_identity_config(config_file)
            assert config["exclude_apps"] == ["debug_app"]

    def test_hardware_identity_config_exclude_apps_whitespace(self):
        """Test exclude_apps with extra whitespace."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("exclude_apps =   app1  ,  app2  ,   app3  \n")
            
            config = load_hardware_identity_config(config_file)
            assert config["exclude_apps"] == ["app1", "app2", "app3"]

    def test_hardware_identity_config_all_settings(self):
        """Test parsing all settings together."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("enabled = true\n")
                f.write("provider = libykcs11\n")
                f.write("token_label = YubiKey PIV #12345\n")
                f.write("exclude_apps = my_test_tool, debug_app, another_app\n")
            
            config = load_hardware_identity_config(config_file)
            
            assert config["enabled"] is True
            assert config["provider"] == "libykcs11"
            assert config["token_label"] == "YubiKey PIV #12345"
            assert config["exclude_apps"] == ["my_test_tool", "debug_app", "another_app"]

    def test_hardware_identity_config_malformed(self):
        """Test graceful handling of malformed config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            # Write malformed config
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("this is not valid ini format\n")
            
            # Should not raise, should return defaults
            config = load_hardware_identity_config(config_file)
            assert config["enabled"] is False
            assert config["provider"] is None

    def test_hardware_identity_config_missing_provider_file(self):
        """Test warning logged when provider file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config")
            
            with open(config_file, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("enabled = true\n")
                f.write("provider = /nonexistent/path/libykcs11.so\n")
            
            # Should not raise, should return config with warning
            config = load_hardware_identity_config(config_file)
            assert config["enabled"] is True
            assert config["provider"] == "/nonexistent/path/libykcs11.so"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
