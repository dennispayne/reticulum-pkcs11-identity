"""
Integration test: end-to-end app identity allocation with backend.
"""

import os
import tempfile
import pytest

from reticulum_pkcs11_identity.app_identity import AppIdentityMapper, PIV_SLOTS
from reticulum_pkcs11_identity.pkcs11_provider import (
    discover_providers,
    get_default_provider,
    detect_provider_type,
)
from reticulum_pkcs11_identity.exceptions import (
    SlotNotFoundError,
    SlotAlreadyOccupiedError,
    PKCS11ProviderNotFoundError,
)


class TestAppIdentityMapper:
    """Test app-to-slot mapper with persistence."""

    def test_discover_providers(self):
        """Verify provider discovery works."""
        providers = discover_providers()
        # On a fresh Windows, might be empty. That's OK.
        assert isinstance(providers, list)

    def test_get_default_provider_with_override(self):
        """Test override provider."""
        # Override with a fake path should fail
        with pytest.raises(PKCS11ProviderNotFoundError):
            get_default_provider(override="/fake/path/libykcs11.dll")

    def test_detect_provider_type(self):
        """Test provider type detection."""
        assert detect_provider_type("/usr/lib/libykcs11.so") == "yubico"
        assert detect_provider_type("/usr/lib/opensc-pkcs11.so") == "opensc"
        assert detect_provider_type("/usr/lib/softhsm/libsofthsm2.so") == "softhsm"
        assert detect_provider_type("/usr/lib/foobar.so") == "unknown"

    def test_mapper_basic_allocation(self):
        """Test basic first-come-first-served allocation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            # Allocate first app
            slot1 = mapper.allocate_slot_for_app("sideband")
            assert slot1 == "9a"
            
            # Allocate second app
            slot2 = mapper.allocate_slot_for_app("meshchat")
            assert slot2 == "9c"
            
            # Allocate third app
            slot3 = mapper.allocate_slot_for_app("rngit")
            assert slot3 == "9d"
            
            # Fourth app
            slot4 = mapper.allocate_slot_for_app("rnphone_solo")
            assert slot4 == "9e"
            
            # Fifth app should fail (all slots full)
            with pytest.raises(SlotNotFoundError):
                mapper.allocate_slot_for_app("app_5")

    def test_mapper_persistence(self):
        """Test mapping persists across restarts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # First session
            mapper1 = AppIdentityMapper(config_dir=tmpdir)
            slot1 = mapper1.allocate_slot_for_app("sideband")
            assert slot1 == "9a"
            
            # Second session - load from disk
            mapper2 = AppIdentityMapper(config_dir=tmpdir)
            assert mapper2.get_app_slot("sideband") == "9a"
            assert mapper2.allocate_slot_for_app("sideband") == "9a"  # No change

    def test_mapper_slot_sharing(self):
        """Test multiple apps sharing a slot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            # First app takes slot
            mapper.allocate_slot_for_app("meshchat")
            assert mapper.get_app_slot("meshchat") == "9a"
            
            # Share same slot with another app
            mapper.share_slot("9a", "rnphone")
            assert mapper.get_app_slot("rnphone") == "9a"
            
            # Both apps should be on same slot
            apps = mapper.get_slot_apps("9a")
            assert "meshchat" in apps
            assert "rnphone" in apps
            assert len(apps) == 2

    def test_mapper_unmap(self):
        """Test unmapping an app."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            slot1 = mapper.allocate_slot_for_app("sideband")
            assert mapper.get_app_slot("sideband") == "9a"
            
            # Unmap app
            returned_slot = mapper.unmap_app("sideband")
            assert returned_slot == "9a"
            assert mapper.get_app_slot("sideband") is None
            
            # Slot should now be available
            assert mapper.is_slot_available("9a")

    def test_mapper_slot_sharing_error(self):
        """Test error when app already on different slot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            mapper.allocate_slot_for_app("app1")  # -> 9a
            mapper.allocate_slot_for_app("app2")  # -> 9c
            
            # Try to share slot 9d with app1 (already on 9a)
            with pytest.raises(SlotAlreadyOccupiedError):
                mapper.share_slot("9d", "app1")

    def test_mapper_repr(self):
        """Test string representation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            mapper.allocate_slot_for_app("sideband")
            mapper.allocate_slot_for_app("meshchat")
            
            repr_str = repr(mapper)
            assert "AppIdentityMapper" in repr_str
            assert "sideband" in repr_str
            assert "meshchat" in repr_str
            assert "[available]" in repr_str


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
