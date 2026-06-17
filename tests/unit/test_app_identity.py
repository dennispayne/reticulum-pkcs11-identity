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
            
            # Allocate first app with explicit filepath
            slot1 = mapper.allocate_slot_for_app("sideband", "/home/user/.reticulum/storage/identities/sideband.identity")
            assert slot1 == "9a"
            
            # Allocate second app with explicit filepath
            slot2 = mapper.allocate_slot_for_app("meshchat", "/home/user/.reticulum/storage/identities/meshchat.identity")
            assert slot2 == "9c"
            
            # Allocate third app
            slot3 = mapper.allocate_slot_for_app("rngit", "/home/user/.reticulum/storage/identities/rngit.identity")
            assert slot3 == "9d"
            
            # Fourth app
            slot4 = mapper.allocate_slot_for_app("rnphone_solo", "/home/user/.reticulum/storage/identities/rnphone_solo.identity")
            assert slot4 == "9e"
            
            # Fifth app should fail (all slots full)
            with pytest.raises(SlotNotFoundError):
                mapper.allocate_slot_for_app("app_5", "/home/user/.reticulum/storage/identities/app_5.identity")

    def test_mapper_filepath_lookup(self):
        """Test filepath-based lookup (new primary API)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            filepath = "/home/user/.reticulum/storage/identities/meshchat.identity"
            
            # No mapping yet
            assert mapper.lookup_identity_for_filepath(filepath) is None
            
            # Allocate
            slot = mapper.allocate_slot_for_app("meshchat", filepath)
            assert slot == "9a"
            
            # Now lookup works
            assert mapper.lookup_identity_for_filepath(filepath) == "9a"

    def test_mapper_persistence(self):
        """Test mapping persists across restarts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = "/home/user/.reticulum/storage/identities/sideband.identity"
            
            # First session
            mapper1 = AppIdentityMapper(config_dir=tmpdir)
            slot1 = mapper1.allocate_slot_for_app("sideband", filepath)
            assert slot1 == "9a"
            
            # Second session - load from disk
            mapper2 = AppIdentityMapper(config_dir=tmpdir)
            
            # Lookup by filepath
            assert mapper2.lookup_identity_for_filepath(filepath) == "9a"
            
            # Backward compat: lookup by app name
            assert mapper2.get_app_slot("sideband") == "9a"
            
            # Allocate same app again - should return same slot
            assert mapper2.allocate_slot_for_app("sideband", filepath) == "9a"

    def test_mapper_exclusion_list(self):
        """Test apps in exclusion list don't get hardware slots."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir, exclude_apps=["debug_app"])
            
            # Normal app gets slot
            slot1 = mapper.allocate_slot_for_app("meshchat", "/home/user/.reticulum/storage/identities/meshchat.identity")
            assert slot1 == "9a"
            
            # Excluded app returns None
            slot2 = mapper.allocate_slot_for_app("debug_app", "/home/user/.reticulum/storage/identities/debug_app.identity")
            assert slot2 is None
            
            # Check exclusion method
            assert mapper.is_app_excluded("debug_app")
            assert not mapper.is_app_excluded("meshchat")

    def test_mapper_exclusion_in_lookup(self):
        """Test that excluded apps return None on lookup even if mapped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper1 = AppIdentityMapper(config_dir=tmpdir)
            filepath = "/home/user/.reticulum/storage/identities/testapp.identity"
            
            # First, allocate without exclusion
            slot = mapper1.allocate_slot_for_app("testapp", filepath)
            assert slot == "9a"
            assert mapper1.lookup_identity_for_filepath(filepath) == "9a"
            
            # Now create mapper with exclusion
            mapper2 = AppIdentityMapper(config_dir=tmpdir, exclude_apps=["testapp"])
            
            # Lookup should return None (app is excluded)
            assert mapper2.lookup_identity_for_filepath(filepath) is None

    def test_mapper_slot_sharing(self):
        """Test multiple apps sharing a slot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            filepath1 = "/home/user/.reticulum/storage/identities/meshchat.identity"
            filepath2 = "/home/user/.reticulum/storage/identities/rnphone.identity"
            
            # First app takes slot
            mapper.allocate_slot_for_app("meshchat", filepath1)
            assert mapper.lookup_identity_for_filepath(filepath1) == "9a"
            
            # Share same slot with another app
            mapper.share_slot("9a", "rnphone", filepath2)
            assert mapper.lookup_identity_for_filepath(filepath2) == "9a"
            
            # Both apps should be on same slot
            apps = mapper.get_slot_apps("9a")
            assert "meshchat" in apps
            assert "rnphone" in apps
            assert len(apps) == 2

    def test_mapper_unmap(self):
        """Test unmapping an app."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            filepath = "/home/user/.reticulum/storage/identities/sideband.identity"
            
            slot1 = mapper.allocate_slot_for_app("sideband", filepath)
            assert mapper.lookup_identity_for_filepath(filepath) == "9a"
            
            # Unmap app
            returned_slot = mapper.unmap_app("sideband")
            assert returned_slot == "9a"
            assert mapper.lookup_identity_for_filepath(filepath) is None
            
            # Slot should now be available
            assert mapper.is_slot_available("9a")

    def test_mapper_slot_sharing_error(self):
        """Test error when app already on different slot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            filepath1 = "/home/user/.reticulum/storage/identities/app1.identity"
            filepath2 = "/home/user/.reticulum/storage/identities/app2.identity"
            filepath3 = "/home/user/.reticulum/storage/identities/app3.identity"
            
            mapper.allocate_slot_for_app("app1", filepath1)  # -> 9a
            mapper.allocate_slot_for_app("app2", filepath2)  # -> 9c
            
            # Try to share slot 9d with app1 (already on 9a)
            with pytest.raises(SlotAlreadyOccupiedError):
                mapper.share_slot("9d", "app1", filepath3)

    def test_mapper_repr(self):
        """Test string representation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir, exclude_apps=["excluded_app"])
            mapper.allocate_slot_for_app("sideband", "/home/user/.reticulum/storage/identities/sideband.identity")
            mapper.allocate_slot_for_app("meshchat", "/home/user/.reticulum/storage/identities/meshchat.identity")
            
            repr_str = repr(mapper)
            assert "AppIdentityMapper" in repr_str
            assert "sideband" in repr_str
            assert "meshchat" in repr_str
            assert "[available]" in repr_str
            assert "excluded_app" in repr_str

    def test_mapper_backward_compat_get_app_slot(self):
        """Test backward compatibility of get_app_slot by app name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            filepath = "/home/user/.reticulum/storage/identities/testapp.identity"
            
            # Allocate with filepath
            slot = mapper.allocate_slot_for_app("testapp", filepath)
            assert slot == "9a"
            
            # Get by app name (backward compat method)
            assert mapper.get_app_slot("testapp") == "9a"

    def test_mapper_corrupted_config_graceful_rebuild(self):
        """Test graceful handling of corrupted config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "pkcs11_app_slots.json")
            
            # Write corrupted JSON
            with open(config_file, "w") as f:
                f.write("{ this is not valid json }")
            
            # Should not raise, should just log warning and rebuild
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            # Should be empty and ready to use
            assert len(mapper._mapping) == 0
            
            # Should be able to allocate normally
            slot = mapper.allocate_slot_for_app("testapp", "/home/user/.reticulum/storage/identities/testapp.identity")
            assert slot == "9a"

    def test_mapper_json_format(self):
        """Test that mapping is saved in JSON format (not old INI format)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            
            filepath = "/home/user/.reticulum/storage/identities/meshchat.identity"
            mapper.allocate_slot_for_app("meshchat", filepath)
            
            # Check file is JSON
            with open(mapper.config_file, "r") as f:
                content = f.read()
                assert "{" in content  # JSON should have braces
                assert "slot" in content
                assert "app_name" in content
                assert "meshchat" in content


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
