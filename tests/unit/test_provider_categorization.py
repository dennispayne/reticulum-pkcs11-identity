"""
Tests for provider categorization and selection (v21 feature).

Tests the new categorize_providers() and select_provider() functions
that query CKF_HW_SLOT flags and categorize providers into hardware/software/unknown.
"""

import logging
import unittest.mock as mock

import pkcs11
import pytest

from reticulum_pkcs11_identity.discovery import (
    categorize_providers,
    select_provider,
    _is_hardware_provider,
    _get_provider_label,
)


# ---------------------------------------------------------------------------
# Fake objects for mocking
# ---------------------------------------------------------------------------

class _FakeSlot:
    """Fake PKCS#11 slot with flags."""
    def __init__(self, slot_id, flags):
        self.slot_id = slot_id
        self.flags = flags


class _FakeLib:
    """Fake PKCS#11 library."""
    def __init__(self, slots):
        self._slots = slots

    def get_slots(self):
        return self._slots


# ---------------------------------------------------------------------------
# Tests for _is_hardware_provider
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestIsHardwareProvider:
    def test_returns_true_for_hw_slot(self, monkeypatch):
        from pkcs11 import SlotFlag
        fake_lib = _FakeLib([_FakeSlot(0, SlotFlag.HW_SLOT)])
        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)

        result = _is_hardware_provider("/fake/libhw.so")
        assert result is True

    def test_returns_false_for_software_slot(self, monkeypatch):
        from pkcs11 import SlotFlag
        fake_lib = _FakeLib([_FakeSlot(0, SlotFlag.TOKEN_PRESENT)])
        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)

        result = _is_hardware_provider("/fake/libsw.so")
        assert result is False

    def test_returns_false_on_lib_load_failure(self, monkeypatch):
        monkeypatch.setattr(
            pkcs11, "lib", lambda _: (_ for _ in ()).throw(RuntimeError())
        )
        result = _is_hardware_provider("/nonexistent/lib.so")
        assert result is False

    def test_returns_false_on_get_slots_failure(self, monkeypatch):
        fake_lib = mock.MagicMock()
        fake_lib.get_slots.side_effect = RuntimeError()
        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)

        result = _is_hardware_provider("/fake/lib.so")
        assert result is False

    def test_returns_true_if_any_slot_has_hw_flag(self, monkeypatch):
        from pkcs11 import SlotFlag
        fake_lib = _FakeLib([
            _FakeSlot(0, SlotFlag.TOKEN_PRESENT),
            _FakeSlot(1, SlotFlag.HW_SLOT),
        ])
        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)

        result = _is_hardware_provider("/fake/lib.so")
        assert result is True


# ---------------------------------------------------------------------------
# Tests for _get_provider_label
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestGetProviderLabel:
    def test_returns_label_for_softhsm(self):
        label = _get_provider_label("/usr/lib/softhsm/libsofthsm2.so")
        assert "SoftHSM2" in label

    def test_returns_label_for_opensc(self):
        label = _get_provider_label("/usr/lib/opensc-pkcs11.so")
        assert "OpenSC" in label

    def test_returns_label_for_yubikey(self):
        label = _get_provider_label("/usr/lib/libykcs11.so")
        assert "YubiKey" in label

    def test_returns_unknown_for_unrecognized(self):
        label = _get_provider_label("/usr/lib/libunknown.so")
        assert "Unknown" in label


# ---------------------------------------------------------------------------
# Tests for categorize_providers
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestCategorizeProviders:
    def test_returns_dict_with_required_keys(self):
        result = categorize_providers()
        assert "hardware" in result
        assert "software" in result
        assert "unknown" in result
        assert isinstance(result["hardware"], list)
        assert isinstance(result["software"], list)
        assert isinstance(result["unknown"], list)

    def test_categorizes_softhsm_as_software(self, tmp_path, monkeypatch):
        lib_file = tmp_path / "softhsm2.so"
        lib_file.touch()
        
        fake_lib = _FakeLib([_FakeSlot(0, 0)])  # No HW_SLOT
        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)
        
        # Mock discover_pkcs11_modules to return only our test library
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
            lambda _: [str(lib_file)]
        )
        
        result = categorize_providers(additional_paths=[str(lib_file)])
        
        assert len(result["software"]) > 0
        assert any("softhsm" in p["name"] for p in result["software"])

    def test_categorizes_opensc_as_hardware(self, tmp_path, monkeypatch):
        from pkcs11 import SlotFlag
        
        lib_file = tmp_path / "opensc-pkcs11.so"
        lib_file.touch()
        
        fake_lib = _FakeLib([_FakeSlot(0, SlotFlag.HW_SLOT)])
        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)
        
        # Mock discover_pkcs11_modules to return only our test library
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
            lambda _: [str(lib_file)]
        )
        
        result = categorize_providers(additional_paths=[str(lib_file)])
        
        assert len(result["hardware"]) > 0
        assert any("opensc" in p["name"] for p in result["hardware"])

    def test_includes_provider_name_path_label(self, tmp_path, monkeypatch):
        lib_file = tmp_path / "test-provider.so"
        lib_file.touch()
        
        fake_lib = _FakeLib([_FakeSlot(0, 0)])
        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)
        
        # Mock discover_pkcs11_modules to return only our test library
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
            lambda _: [str(lib_file)]
        )
        
        result = categorize_providers(additional_paths=[str(lib_file)])
        
        # Should be in unknown or software
        all_providers = result["software"] + result["unknown"]
        assert len(all_providers) > 0
        provider = all_providers[0]
        assert "name" in provider
        assert "path" in provider
        assert "label" in provider
        assert provider["path"] == str(lib_file)

    def test_empty_on_no_modules(self, monkeypatch):
        # Mock discover_pkcs11_modules to return empty list
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
            lambda _: []
        )
        
        result = categorize_providers(additional_paths=[])
        assert len(result["hardware"]) == 0
        assert len(result["software"]) == 0
        assert len(result["unknown"]) == 0

    def test_handles_module_load_failure_gracefully(self, tmp_path, monkeypatch):
        lib_file = tmp_path / "broken.so"
        lib_file.touch()
        
        monkeypatch.setattr(
            pkcs11, "lib", lambda _: (_ for _ in ()).throw(RuntimeError())
        )
        
        # Mock discover_pkcs11_modules to return only our test library
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
            lambda _: [str(lib_file)]
        )
        
        result = categorize_providers(additional_paths=[str(lib_file)])
        
        # Should still include it in unknown
        all_providers = result["unknown"]
        assert len(all_providers) > 0


# ---------------------------------------------------------------------------
# Tests for select_provider
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestSelectProvider:
    def test_selects_single_hardware_provider(self, caplog):
        categorized = {
            "hardware": [{"name": "opensc", "path": "/usr/lib/opensc.so", "label": "OpenSC"}],
            "software": [],
            "unknown": [],
        }
        
        with caplog.at_level(logging.INFO):
            result = select_provider(categorized)
        
        assert result is not None
        assert result["name"] == "opensc"
        assert "Selected hardware provider" in caplog.text

    def test_returns_none_for_multiple_hardware_providers(self, caplog):
        categorized = {
            "hardware": [
                {"name": "opensc", "path": "/usr/lib/opensc.so", "label": "OpenSC"},
                {"name": "ykcs11", "path": "/usr/lib/ykcs11.so", "label": "YubiKey"},
            ],
            "software": [],
            "unknown": [],
        }
        
        with caplog.at_level(logging.WARNING):
            result = select_provider(categorized)
        
        assert result is None
        assert "Multiple hardware providers" in caplog.text

    def test_selects_software_when_no_hardware(self, caplog):
        categorized = {
            "hardware": [],
            "software": [{"name": "softhsm", "path": "/usr/lib/softhsm2.so", "label": "SoftHSM2"}],
            "unknown": [],
        }
        
        with caplog.at_level(logging.INFO):
            result = select_provider(categorized)
        
        assert result is not None
        assert result["name"] == "softhsm"
        assert "No hardware provider found" in caplog.text

    def test_returns_none_when_no_providers(self, caplog):
        categorized = {
            "hardware": [],
            "software": [],
            "unknown": [],
        }
        
        with caplog.at_level(logging.WARNING):
            result = select_provider(categorized)
        
        assert result is None
        assert "No PKCS#11 providers found" in caplog.text

    def test_prioritizes_hardware_over_software(self, caplog):
        categorized = {
            "hardware": [{"name": "opensc", "path": "/usr/lib/opensc.so", "label": "OpenSC"}],
            "software": [{"name": "softhsm", "path": "/usr/lib/softhsm2.so", "label": "SoftHSM2"}],
            "unknown": [],
        }
        
        with caplog.at_level(logging.INFO):
            result = select_provider(categorized)
        
        assert result is not None
        assert result["name"] == "opensc"

    def test_selection_log_includes_provider_info(self, caplog):
        categorized = {
            "hardware": [{"name": "opensc", "path": "/usr/lib/opensc.so", "label": "OpenSC PIV"}],
            "software": [],
            "unknown": [],
        }
        
        with caplog.at_level(logging.INFO):
            select_provider(categorized)
        
        assert "opensc" in caplog.text
        assert "OpenSC PIV" in caplog.text
        assert "/usr/lib/opensc.so" in caplog.text

    def test_handles_missing_keys_gracefully(self):
        # Categorized dict might be missing some keys
        categorized = {}
        result = select_provider(categorized)
        assert result is None

    def test_empty_hardware_list_treated_as_zero(self, caplog):
        categorized = {
            "hardware": [],
            "software": [{"name": "softhsm", "path": "/usr/lib/softhsm2.so", "label": "SoftHSM2"}],
            "unknown": [],
        }
        
        with caplog.at_level(logging.INFO):
            result = select_provider(categorized)
        
        assert result is not None
        assert result["name"] == "softhsm"
        assert "No hardware provider found" in caplog.text


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.discovery
class TestProviderCategorizationIntegration:
    def test_full_workflow(self, tmp_path, monkeypatch):
        """Test categorize_providers -> select_provider workflow."""
        from pkcs11 import SlotFlag
        
        # Create fake providers
        hw_lib = tmp_path / "libhw.so"
        hw_lib.touch()
        
        sw_lib = tmp_path / "libsw.so"
        sw_lib.touch()
        
        libs = {
            str(hw_lib): _FakeLib([_FakeSlot(0, SlotFlag.HW_SLOT)]),
            str(sw_lib): _FakeLib([_FakeSlot(0, SlotFlag.TOKEN_PRESENT)]),
        }
        
        monkeypatch.setattr(
            pkcs11, "lib", lambda path: libs.get(path, _FakeLib([]))
        )
        
        # Mock discover_pkcs11_modules to return only our test libraries
        monkeypatch.setattr(
            "reticulum_pkcs11_identity.discovery.discover_pkcs11_modules",
            lambda _: [str(hw_lib), str(sw_lib)]
        )
        
        # Categorize
        result = categorize_providers(
            additional_paths=[str(hw_lib), str(sw_lib)]
        )
        
        # Should have providers
        assert len(result["hardware"]) > 0 or len(result["software"]) > 0
        
        # Select
        selected = select_provider(result)
        
        # Should prefer hardware
        if result["hardware"]:
            assert selected is not None
            assert selected["path"] == str(hw_lib)
        elif result["software"]:
            assert selected is not None
            assert selected["path"] == str(sw_lib)
