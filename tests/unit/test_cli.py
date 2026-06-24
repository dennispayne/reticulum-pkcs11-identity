"""Tests for the CLI module."""

import sys
from unittest.mock import patch, MagicMock

from reticulum_pkcs11_identity.cli import StatusReporter
import reticulum_pkcs11_identity.cli as cli


def _reporter(config=None):
    """Build a StatusReporter with a mocked config."""
    cfg = config or {
        "enabled": False,
        "provider": None,
        "token_label": None,
        "detected_providers": {},
    }
    with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config", return_value=cfg):
        return StatusReporter()


class TestStatusReporter:
    """Test StatusReporter functionality."""

    def test_configuration_section_disabled(self):
        """Test configuration section when disabled."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "provider": None,
                "token_label": None,
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
                "detected_providers": {}
            }

            reporter = StatusReporter()
            rows = reporter.get_configuration_section()

            # Verify rows
            assert any("Enabled" in str(row) and "[+] Yes" in str(row) for row in rows)
            assert any("libykcs11" in str(row) for row in rows)
            assert any("YubiKey PIV" in str(row) for row in rows)

    def test_warnings_section(self):
        """Test warnings generation."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "provider": None,
                "token_label": None,
                "detected_providers": {}
            }

            reporter = StatusReporter()
            # Need to call get_configuration_section first to populate warnings
            reporter.get_configuration_section()
            warnings = reporter.get_warnings_section()

            # Should have warning for provider not configured
            assert any("Provider" in str(w) for w in warnings)

    def test_print_status_output(self, capsys):
        """Test status output formatting."""
        with patch("reticulum_pkcs11_identity.cli.load_hardware_identity_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "provider": "/usr/lib/libykcs11.so",
                "token_label": "YubiKey PIV",
                "detected_providers": {}
            }

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

    def test_query_token_info_no_provider(self):
        reporter = _reporter()
        assert reporter._query_token_info() is None

    def test_query_token_info_match(self):
        cfg = {
            "enabled": True,
            "provider": "/lib/p11.so",
            "token_label": "MyToken",
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
            "detected_providers": {},
        }
        reporter = _reporter(cfg)
        with patch.object(reporter, "_query_token_info",
                          return_value={"serial": "S1"}):
            rows = reporter.get_configuration_section()
        assert any("Token (serial)" in str(r) and "S1" in str(r) for r in rows)

    def test_warnings_multiple_hardware_providers(self):
        cfg = {
            "enabled": True,
            "provider": "/lib/p11.so",
            "token_label": "T",
            "detected_providers": {
                "p1": {"type": "hardware"},
                "p2": {"type": "hardware"},
            },
        }
        reporter = _reporter(cfg)
        warnings = reporter.get_warnings_section()
        assert any("Multiple hardware providers" in w for w in warnings)


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
