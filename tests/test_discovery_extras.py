"""
Tests for discovery.py error paths, edge cases, and formatting — no PKCS#11
token required.
"""

import unittest.mock as mock

import pkcs11
import pytest

from reticulum_pkcs11_identity.discovery import (
    _has_public_key,
    _provider_hint,
    _provider_type,
    discover_module_paths,
    enumerate_token_inventory,
    format_token_inventory,
)


# ---------------------------------------------------------------------------
# Provider hint / type helpers
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestProviderHelpers:
    def test_unknown_module_returns_unknown_provider(self):
        assert _provider_hint("/opt/custom/libunknown.so") == "Unknown provider"

    def test_softhsm_recognized(self):
        assert _provider_hint("/usr/lib/softhsm/libsofthsm2.so") == "SoftHSM2"

    def test_yubikey_recognized(self):
        assert _provider_hint("/usr/lib/libykcs11.so") == "YubiKey PIV"

    def test_unknown_module_returns_unknown_type(self):
        assert _provider_type("/opt/custom/libunknown.so") == "unknown"

    def test_softhsm_is_software_type(self):
        assert _provider_type("/usr/lib/softhsm/libsofthsm2.so") == "software"

    def test_opensc_is_hardware_type(self):
        assert _provider_type("/usr/lib/opensc-pkcs11.so") == "hardware"


# ---------------------------------------------------------------------------
# discover_module_paths
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestDiscoverModulePaths:
    def test_additional_path_included_when_file_exists(self, tmp_path):
        lib = tmp_path / "libfake.so"
        lib.touch()
        result = discover_module_paths(additional_paths=[str(lib)])
        assert str(lib) in result

    def test_nonexistent_additional_path_excluded(self):
        result = discover_module_paths(additional_paths=["/nonexistent/lib.so"])
        assert "/nonexistent/lib.so" not in result

    def test_duplicate_paths_deduplicated(self, tmp_path):
        lib = tmp_path / "lib.so"
        lib.touch()
        path = str(lib)
        result = discover_module_paths(additional_paths=[path, path])
        assert result.count(path) == 1

    def test_empty_string_paths_ignored(self):
        result = discover_module_paths(additional_paths=[""])
        # Empty string should not appear in results
        assert "" not in result


# ---------------------------------------------------------------------------
# _has_public_key edge cases
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestHasPublicKey:
    def test_empty_label_returns_false_without_calling_session(self):
        fake_session = mock.MagicMock()
        assert _has_public_key(fake_session, "") is False
        fake_session.get_key.assert_not_called()

    def test_multiple_objects_returned_counts_as_present(self):
        fake_session = mock.MagicMock()
        fake_session.get_key.side_effect = pkcs11.exceptions.MultipleObjectsReturned()
        assert _has_public_key(fake_session, "lxmf-sign") is True

    def test_no_such_key_returns_false(self):
        fake_session = mock.MagicMock()
        fake_session.get_key.side_effect = pkcs11.exceptions.NoSuchKey()
        assert _has_public_key(fake_session, "lxmf-sign") is False


# ---------------------------------------------------------------------------
# enumerate_token_inventory — error paths
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestEnumerateTokenInventoryErrors:
    def test_module_load_failure_produces_error_row(self, monkeypatch):
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.pkcs11.lib",
            lambda _path: (_ for _ in ()).throw(RuntimeError("bad module")),
        )

        rows = enumerate_token_inventory(module_paths=["/fake/lib.so"])

        assert len(rows) == 1
        assert rows[0]["identity_status"] == "unknown"
        assert "module load failed" in rows[0]["error"]

    def test_slot_enumeration_failure_produces_error_row(self, monkeypatch):
        fake_lib = mock.MagicMock()
        fake_lib.get_slots.side_effect = RuntimeError("slots unavailable")
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.pkcs11.lib",
            lambda _path: fake_lib,
        )

        rows = enumerate_token_inventory(module_paths=["/fake/lib.so"])

        assert len(rows) == 1
        assert rows[0]["identity_status"] == "unknown"
        assert "slot enumeration failed" in rows[0]["error"]

    def test_token_read_failure_produces_error_row(self, monkeypatch):
        fake_slot = mock.MagicMock()
        fake_slot.slot_id = 1
        fake_slot.get_token.side_effect = RuntimeError("token read failed")
        fake_lib = mock.MagicMock()
        fake_lib.get_slots.return_value = [fake_slot]
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.pkcs11.lib",
            lambda _path: fake_lib,
        )

        rows = enumerate_token_inventory(module_paths=["/fake/lib.so"])

        assert len(rows) == 1
        assert rows[0]["identity_status"] == "unknown"
        assert "token read failed" in rows[0]["error"]

    def test_key_probe_failure_sets_error_field(self, monkeypatch):
        fake_token = mock.MagicMock()
        fake_token.label = "TestToken"
        fake_token.serial = "SER001"
        fake_token.open.side_effect = RuntimeError("probe failed")
        fake_slot = mock.MagicMock()
        fake_slot.slot_id = 1
        fake_slot.get_token.return_value = fake_token
        fake_lib = mock.MagicMock()
        fake_lib.get_slots.return_value = [fake_slot]
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.pkcs11.lib",
            lambda _path: fake_lib,
        )

        rows = enumerate_token_inventory(module_paths=["/fake/lib.so"])

        assert len(rows) == 1
        assert rows[0]["identity_status"] == "unknown"
        assert "key probe failed" in rows[0]["error"]

    def test_both_keys_missing_sets_status_missing(self, monkeypatch):
        fake_session = mock.MagicMock()
        fake_session.get_key.side_effect = pkcs11.exceptions.NoSuchKey()
        fake_token = mock.MagicMock()
        fake_token.label = "TestToken"
        fake_token.serial = "SER001"
        fake_token.open.return_value = fake_session
        fake_slot = mock.MagicMock()
        fake_slot.slot_id = 1
        fake_slot.get_token.return_value = fake_token
        fake_lib = mock.MagicMock()
        fake_lib.get_slots.return_value = [fake_slot]
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.pkcs11.lib",
            lambda _path: fake_lib,
        )

        rows = enumerate_token_inventory(module_paths=["/fake/lib.so"])

        assert len(rows) == 1
        assert rows[0]["identity_status"] == "missing"
        assert rows[0]["has_sign_key"] is False
        assert rows[0]["has_enc_key"] is False

    def test_token_label_filter_excludes_non_matching(self, monkeypatch):
        fake_token = mock.MagicMock()
        fake_token.label = "WrongLabel"
        fake_token.serial = "SER001"
        fake_slot = mock.MagicMock()
        fake_slot.slot_id = 1
        fake_slot.get_token.return_value = fake_token
        fake_lib = mock.MagicMock()
        fake_lib.get_slots.return_value = [fake_slot]
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.pkcs11.lib",
            lambda _path: fake_lib,
        )

        rows = enumerate_token_inventory(
            module_paths=["/fake/lib.so"], token_label="CorrectLabel"
        )

        assert len(rows) == 0


# ---------------------------------------------------------------------------
# format_token_inventory
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestFormatTokenInventory:
    def test_empty_returns_no_providers_message(self):
        result = format_token_inventory([])
        assert "No PKCS#11 providers" in result

    def test_normal_row_formatted(self):
        row = {
            "provider_hint": "SoftHSM2",
            "provider_type": "software",
            "module_path": "/usr/lib/softhsm/libsofthsm2.so",
            "token_label": "TestToken",
            "serial": "001",
            "slot_id": 1,
            "identity_status": "ready",
            "has_sign_key": True,
            "has_enc_key": True,
        }
        result = format_token_inventory([row])
        assert "SoftHSM2" in result
        assert "TestToken" in result
        assert "ready" in result

    def test_error_row_includes_note_line(self):
        row = {
            "provider_hint": "SoftHSM2",
            "provider_type": "software",
            "module_path": "/lib/softhsm2.so",
            "token_label": "TestToken",
            "serial": "001",
            "slot_id": 1,
            "identity_status": "unknown",
            "has_sign_key": None,
            "has_enc_key": None,
            "error": "module load failed: oops",
        }
        result = format_token_inventory([row])
        assert "note: module load failed: oops" in result

    def test_multiple_rows_all_numbered(self):
        rows = [
            {
                "provider_hint": "SoftHSM2",
                "provider_type": "software",
                "module_path": "/lib/softhsm2.so",
                "token_label": f"Token{i}",
                "serial": f"SER{i:03d}",
                "slot_id": i,
                "identity_status": "ready",
                "has_sign_key": True,
                "has_enc_key": True,
            }
            for i in range(3)
        ]
        result = format_token_inventory(rows)
        assert "[1]" in result
        assert "[2]" in result
        assert "[3]" in result
