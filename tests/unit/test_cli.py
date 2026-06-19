"""Tests for the CLI module."""

import io
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from reticulum_pkcs11_identity.cli import StatusReporter
import reticulum_pkcs11_identity.cli as cli


def _reporter(config=None, mapper=True):
    """Build a StatusReporter with a mocked config (and optional mapper)."""
    cfg = config or {
        "enabled": False,
        "provider": None,
        "token_label": None,
        "exclude_apps": [],
        "detected_providers": {},
    }
    with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config", return_value=cfg):
        if mapper:
            with patch("reticulum_pkcs11_identity.cli.AppIdentityMapper"):
                return StatusReporter()
        return StatusReporter()


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


class TestStatusReporterExtras:
    """Cover remaining StatusReporter branches."""

    def test_detect_running_apps_subprocess(self):
        reporter = _reporter()
        reporter.running_apps = set()
        fake = MagicMock()
        fake.stdout = "some sideband process here"
        with patch("reticulum_pkcs11_identity.cli.sys.platform", "linux"), \
             patch("reticulum_pkcs11_identity.cli.subprocess.run", return_value=fake):
            reporter._detect_running_apps_subprocess()
        assert "sideband" in reporter.running_apps

    def test_detect_running_apps_subprocess_error(self):
        reporter = _reporter()
        with patch("reticulum_pkcs11_identity.cli.subprocess.run",
                   side_effect=RuntimeError("no ps")):
            reporter._detect_running_apps_subprocess()  # should not raise

    def test_query_token_info_no_provider(self):
        reporter = _reporter()
        assert reporter._query_token_info() is None

    def test_query_token_info_match(self):
        cfg = {
            "enabled": True,
            "provider": "/lib/p11.so",
            "token_label": "MyToken",
            "exclude_apps": [],
            "detected_providers": {},
        }
        reporter = _reporter(cfg)
        inv = [{"token_label": "MyToken", "serial": "ABC123"}]
        with patch("reticulum_pkcs11_identity.cli.enumerate_token_inventory", return_value=inv):
            info = reporter._query_token_info()
        assert info["serial"] == "ABC123"
        assert info["label"] == "MyToken"

    def test_query_token_info_no_match(self):
        cfg = {
            "enabled": True,
            "provider": "/lib/p11.so",
            "token_label": "MyToken",
            "exclude_apps": [],
            "detected_providers": {},
        }
        reporter = _reporter(cfg)
        inv = [{"token_label": "Other", "serial": "X"}]
        with patch("reticulum_pkcs11_identity.cli.enumerate_token_inventory", return_value=inv):
            assert reporter._query_token_info() is None

    def test_configuration_section_includes_token_info(self):
        cfg = {
            "enabled": True,
            "provider": "/lib/p11.so",
            "token_label": "MyToken",
            "exclude_apps": [],
            "detected_providers": {},
        }
        reporter = _reporter(cfg)
        with patch.object(reporter, "_query_token_info",
                          return_value={"serial": "S1", "slots_available": 4}):
            rows = reporter.get_configuration_section()
        assert any("Token (serial)" in str(r) and "S1" in str(r) for r in rows)
        assert any("Slots available" in str(r) for r in rows)

    def test_warnings_multiple_hardware_providers(self):
        cfg = {
            "enabled": True,
            "provider": "/lib/p11.so",
            "token_label": "T",
            "exclude_apps": [],
            "detected_providers": {
                "p1": {"type": "hardware"},
                "p2": {"type": "hardware"},
            },
        }
        reporter = _reporter(cfg)
        warnings = reporter.get_warnings_section()
        assert any("Multiple hardware providers" in w for w in warnings)

    def test_warnings_slot_conflict(self):
        reporter = _reporter()
        reporter.mapper = MagicMock()
        reporter.mapper.get_slot_apps.side_effect = lambda slot: (
            ["a", "b"] if slot == "9a" else []
        )
        warnings = reporter.get_warnings_section()
        assert any("shared by multiple apps" in w for w in warnings)

    def test_apps_section_with_apps(self):
        reporter = _reporter()
        reporter.mapper = MagicMock()
        reporter.mapper._mapping = {"k": {"app_name": "meshchat"}}
        reporter.mapper.is_app_excluded.return_value = False
        reporter.mapper.get_app_slot.return_value = "9c"
        reporter.running_apps = {"meshchat"}
        rows = reporter.get_apps_section()
        assert any(row[0] == "meshchat" for row in rows)


class TestCommands:
    """Test top-level CLI command functions."""

    def test_status_command(self):
        with patch("reticulum_pkcs11_identity.cli.StatusReporter") as SR:
            cli.status_command(None)
        SR.return_value.print_status.assert_called_once()

    def test_list_tokens_no_providers(self, capsys):
        with patch("reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
                   return_value=[]):
            cli.list_tokens_command(None)
        out = capsys.readouterr().out
        assert "No PKCS#11 providers found" in out

    def test_list_tokens_with_token(self, capsys):
        token = MagicMock()
        token.label = "YubiKey PIV"
        token.serial_number = "12345"
        slot = MagicMock()
        slot.slot_id = 0
        slot.get_token.return_value = token
        lib = MagicMock()
        lib.get_slots.return_value = [slot]

        with patch("reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
                   return_value=["/lib/p11.so"]), \
             patch("pkcs11.lib", return_value=lib):
            cli.list_tokens_command(None)
        out = capsys.readouterr().out
        assert "YubiKey PIV" in out
        assert "Token:" in out

    def test_list_tokens_no_slots(self, capsys):
        lib = MagicMock()
        lib.get_slots.return_value = []
        with patch("reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
                   return_value=["/lib/p11.so"]), \
             patch("pkcs11.lib", return_value=lib):
            cli.list_tokens_command(None)
        out = capsys.readouterr().out
        assert "no slots detected" in out

    def test_list_tokens_provider_error(self, capsys):
        with patch("reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
                   return_value=["/lib/p11.so"]), \
             patch("pkcs11.lib", side_effect=Exception("load fail")):
            cli.list_tokens_command(None)
        out = capsys.readouterr().out
        assert "No tokens detected" in out


class TestMain:
    """Test the argparse entry point."""

    def test_main_status_default(self):
        with patch.object(sys, "argv", ["rnidstatus"]), \
             patch("reticulum_pkcs11_identity.cli.status_command") as sc:
            cli.main()
        sc.assert_called_once()

    def test_main_list_tokens(self):
        with patch.object(sys, "argv", ["rnidstatus", "list-tokens"]), \
             patch("reticulum_pkcs11_identity.cli.list_tokens_command") as lt:
            cli.main()
        lt.assert_called_once()

    def test_main_status_subcommand(self):
        with patch.object(sys, "argv", ["rnidstatus", "status"]), \
             patch("reticulum_pkcs11_identity.cli.status_command") as sc:
            cli.main()
        sc.assert_called_once()


class TestPackageEntryPoint:
    """Cover the ``python -m reticulum_pkcs11_identity`` entry point."""

    def test_dunder_main_invokes_cli_main(self):
        import runpy

        with patch("reticulum_pkcs11_identity.cli.main") as mock_main:
            runpy.run_module(
                "reticulum_pkcs11_identity",
                run_name="__main__",
            )
        mock_main.assert_called_once()
