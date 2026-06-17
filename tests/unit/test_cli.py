"""Tests for the CLI module."""

import io
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from reticulum_pkcs11_identity.cli import StatusReporter


class TestStatusReporter:
    """Test StatusReporter functionality."""

    def test_configuration_section_disabled(self, tmp_path):
        """Test configuration section when disabled."""
        # Create temporary config
        config_dir = tmp_path / ".config" / "reticulum"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "config"
        config_file.write_text("""
[hardware_identity]
enabled = false
""")
        
        # Patch config path
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            reporter = StatusReporter()
            rows = reporter.get_configuration_section()
            
            # Verify rows
            assert any("Enabled" in str(row) and "[-] No" in str(row) for row in rows)
            assert any("Provider" in str(row) for row in rows)

    def test_configuration_section_enabled(self):
        """Test configuration section when enabled."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "provider": "/usr/lib/libykcs11.so",
                "token_label": "YubiKey PIV",
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            reporter = StatusReporter()
            rows = reporter.get_configuration_section()
            
            # Verify rows
            assert any("Enabled" in str(row) and "[+] Yes" in str(row) for row in rows)
            assert any("libykcs11" in str(row) for row in rows)
            assert any("YubiKey PIV" in str(row) for row in rows)

    def test_excluded_apps(self):
        """Test configuration with excluded apps."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
                "exclude_apps": ["meshchat", "nomad-network"],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper") as mock_mapper:
                reporter = StatusReporter()
                rows = reporter.get_configuration_section()
                
                # Verify excluded apps are listed
                assert any("meshchat" in str(row) and "nomad-network" in str(row) for row in rows)

    def test_apps_section_no_apps(self):
        """Test apps section when no apps are configured."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper"):
                reporter = StatusReporter()
                rows = reporter.get_apps_section()
                
                # No apps should be shown
                assert len(rows) == 0

    def test_identity_modes(self):
        """Test identity mode determination."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
                "exclude_apps": ["excluded_app"],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper") as mock_mapper_class:
                mock_mapper = MagicMock()
                mock_mapper_class.return_value = mock_mapper
                
                # Configure mock mapper
                mock_mapper.is_app_excluded.side_effect = lambda app: app == "excluded_app"
                mock_mapper.get_app_slot.side_effect = lambda app: "9c" if app == "hw_app" else None
                
                reporter = StatusReporter()
                
                # Test excluded app
                assert reporter._get_identity_mode("excluded_app") == "excluded"
                
                # Test hw-backed app
                assert reporter._get_identity_mode("hw_app") == "hw-backed"
                
                # Test not-configured app
                assert reporter._get_identity_mode("unknown_app") == "not-configured"

    def test_app_slot_display(self):
        """Test app slot display formatting."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
                "exclude_apps": ["excluded_app"],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper") as mock_mapper_class:
                mock_mapper = MagicMock()
                mock_mapper_class.return_value = mock_mapper
                
                # Configure mock mapper
                mock_mapper.is_app_excluded.side_effect = lambda app: app == "excluded_app"
                mock_mapper.get_app_slot.side_effect = lambda app: "9d" if app == "hw_app" else None
                
                reporter = StatusReporter()
                
                # Test excluded app slot display
                assert reporter._get_app_slot("excluded_app") == "(software)"
                
                # Test hw-backed app slot display
                assert reporter._get_app_slot("hw_app") == "PIV:9D"
                
                # Test not-configured app slot display
                assert reporter._get_app_slot("unknown_app") == "(no identity)"

    def test_tokens_section(self):
        """Test tokens section generation."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper") as mock_mapper_class:
                mock_mapper = MagicMock()
                mock_mapper_class.return_value = mock_mapper
                
                # Configure mock mapper to return slots
                def get_slot_apps(slot):
                    slots = {
                        "9a": [],
                        "9c": ["meshchat"],
                        "9d": ["sideband"],
                        "9e": []
                    }
                    return slots.get(slot, [])
                
                mock_mapper.get_slot_apps.side_effect = get_slot_apps
                
                reporter = StatusReporter()
                rows = reporter.get_tokens_section()
                
                # Should have 2 rows for slots 9c and 9d
                assert len(rows) == 2
                assert any("PIV:9C" in str(row) and "meshchat" in str(row) for row in rows)
                assert any("PIV:9D" in str(row) and "sideband" in str(row) for row in rows)

    def test_warnings_section(self):
        """Test warnings generation."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper"):
                reporter = StatusReporter()
                # Need to call get_configuration_section first to populate warnings
                reporter.get_configuration_section()
                warnings = reporter.get_warnings_section()
                
                # Should have warning for provider not configured
                assert any("Provider" in str(w) for w in warnings)

    def test_app_status_detection(self):
        """Test app status detection."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper"):
                reporter = StatusReporter()
                reporter.running_apps = {"meshchat"}
                
                # Test running app
                assert reporter._get_app_status("meshchat") == "running"
                
                # Test stopped app
                assert reporter._get_app_status("sideband") == "stopped"

    def test_print_status_output(self, capsys):
        """Test status output formatting."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "provider": "/usr/lib/libykcs11.so",
                "token_label": "YubiKey PIV",
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper"):
                reporter = StatusReporter()
                reporter.print_status()
                
                captured = capsys.readouterr()
                output = captured.out
                
                # Check for expected sections
                assert "RETICULUM PKCS#11 IDENTITY STATUS" in output
                assert "CONFIGURATION:" in output
                assert "Enabled" in output
                assert "[+] Yes" in output
                assert "Provider" in output
