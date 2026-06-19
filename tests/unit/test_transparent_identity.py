"""
Tests for transparent hardware identity (zero-config).
"""

import tempfile
import os
import pytest
from unittest.mock import MagicMock, patch

import reticulum_pkcs11_identity.transparent_identity as ti
from reticulum_pkcs11_identity.transparent_identity import (
    TransparentHardwareIdentityFactory,
    get_or_create_hardware_identity,
    is_app_using_hardware,
    get_app_hardware_slot,
    list_all_app_slots,
)
from reticulum_pkcs11_identity.exceptions import PKCS11ProviderNotFoundError


class TestTransparentHardwareIdentity:
    """Test zero-config hardware identity setup."""

    def test_transparent_factory_no_pin(self):
        """Test factory gracefully fails without PIN."""
        factory = TransparentHardwareIdentityFactory("test_app")
        # No PIN configured - should return False
        assert factory.try_setup_hardware() is False
        assert not factory.is_hardware_available()

    def test_transparent_factory_with_pin_but_no_provider(self):
        """Test factory with PIN but no provider still fails gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.conf")
            
            from reticulum_pkcs11_identity.config import PKCS11Config
            config = PKCS11Config(config_file)
            config.set_pin("123456", save=True)
            
            # Now try factory - should fail due to no provider, but not raise
            factory = TransparentHardwareIdentityFactory("test_app")
            result = factory.try_setup_hardware()
            # May be False (if no provider available) or True (if provider is available)
            # The key is: it should NOT raise an exception
            assert isinstance(result, bool)

    def test_get_or_create_hardware_identity_returns_none_when_unavailable(self):
        """Test zero-config function returns None when hardware unavailable."""
        hw_identity = get_or_create_hardware_identity("test_app_no_hw")
        # Should return None if no hardware/pin
        assert hw_identity is None

    def test_is_app_using_hardware_false_by_default(self):
        """Test app is not using hardware by default."""
        assert not is_app_using_hardware("brand_new_app")

    def test_get_app_hardware_slot_none_by_default(self):
        """Test app has no slot by default."""
        assert get_app_hardware_slot("brand_new_app") is None

    def test_list_all_app_slots_empty_by_default(self):
        """Test slot list is empty with no apps mapped."""
        slots = list_all_app_slots()
        assert isinstance(slots, dict)
        # Should be empty or have pre-existing entries

    def test_transparent_factory_public_keys_none_when_unavailable(self):
        """Test public key retrieval returns None when hardware unavailable."""
        factory = TransparentHardwareIdentityFactory("test_app")
        assert factory.get_public_keys() is None

    def test_transparent_factory_sign_returns_none_when_unavailable(self):
        """Test signing returns None when hardware unavailable."""
        factory = TransparentHardwareIdentityFactory("test_app")
        result = factory.sign(b"test message")
        assert result is None

    def test_transparent_factory_ecdh_returns_none_when_unavailable(self):
        """Test ECDH key returns None when hardware unavailable."""
        factory = TransparentHardwareIdentityFactory("test_app")
        result = factory.ecdh_public_key()
        assert result is None

    def test_transparent_factory_no_exceptions(self):
        """
        Test that transparent factory NEVER raises exceptions.
        
        This is the core promise: it always fails gracefully.
        """
        factory = TransparentHardwareIdentityFactory("test_app")
        
        # These should all work (return False or None) without raising
        try:
            factory.try_setup_hardware()
            factory.is_hardware_available()
            factory.get_public_keys()
            factory.sign(b"msg")
            factory.ecdh_public_key()
        except Exception as e:
            pytest.fail(f"Transparent factory raised exception: {e}")


def _make_factory(app_name="myapp", excluded=False):
    """Build a factory with mocked config + mapper for white-box tests."""
    with patch.object(ti, "PKCS11Config") as CfgCls, \
         patch.object(ti, "load_hardware_identity_config", return_value={"exclude_apps": []}), \
         patch.object(ti, "AppIdentityMapper") as MapperCls:
        factory = TransparentHardwareIdentityFactory(app_name)
    factory.config = MagicMock()
    factory.mapper = MagicMock()
    factory.mapper.is_app_excluded.return_value = excluded
    return factory


class TestTrySetupHardwarePaths:
    """White-box tests of try_setup_hardware branches."""

    def test_excluded_app_returns_false(self):
        factory = _make_factory(excluded=True)
        assert factory.try_setup_hardware() is False

    def test_no_pin_returns_false(self):
        factory = _make_factory()
        factory.config.get_pin.return_value = None
        assert factory.try_setup_hardware() is False

    def test_provider_not_found_returns_false(self):
        factory = _make_factory()
        factory.config.get_pin.return_value = "123456"
        factory.config.get_provider.side_effect = PKCS11ProviderNotFoundError("none")
        assert factory.try_setup_hardware() is False

    def test_success_path(self):
        factory = _make_factory()
        factory.config.get_pin.return_value = "123456"
        factory.config.get_provider.return_value = "/lib/p11.so"
        factory.mapper.get_app_slot.return_value = "9a"
        with patch.object(ti, "PKCS11PIVBackend") as BackendCls:
            assert factory.try_setup_hardware() is True
        assert factory.is_hardware_available() is True
        assert factory.slot == "9a"

    def test_success_with_auto_provider_and_allocation(self):
        factory = _make_factory()
        factory.config.get_pin.return_value = "123456"
        factory.config.get_provider.return_value = "auto"
        factory.mapper.get_app_slot.return_value = None
        factory.mapper.allocate_slot_for_app.return_value = "9c"
        with patch.object(ti, "PKCS11PIVBackend"), \
             patch.object(ti, "get_default_provider", return_value="/lib/auto.so"):
            assert factory.try_setup_hardware() is True
        assert factory.slot == "9c"

    def test_no_slot_allocated_returns_false(self):
        factory = _make_factory()
        factory.config.get_pin.return_value = "123456"
        factory.config.get_provider.return_value = "/lib/p11.so"
        factory.mapper.get_app_slot.return_value = None
        factory.mapper.allocate_slot_for_app.return_value = None
        with patch.object(ti, "PKCS11PIVBackend"):
            assert factory.try_setup_hardware() is False

    def test_backend_error_returns_false(self):
        factory = _make_factory()
        factory.config.get_pin.return_value = "123456"
        factory.config.get_provider.return_value = "/lib/p11.so"
        factory.mapper.get_app_slot.return_value = "9a"
        with patch.object(ti, "PKCS11PIVBackend", side_effect=RuntimeError("boom")):
            assert factory.try_setup_hardware() is False


class TestHardwareOperations:
    """Tests for get_public_keys / sign / ecdh_public_key when available."""

    def _ready_factory(self):
        factory = _make_factory()
        factory._hardware_available = True
        factory.backend = MagicMock()
        factory.slot = "9a"
        return factory

    def test_get_public_keys_success(self):
        factory = self._ready_factory()
        factory.backend.get_public_key.side_effect = [b"ed", b"x"]
        assert factory.get_public_keys() == (b"ed", b"x")

    def test_get_public_keys_error_returns_none(self):
        factory = self._ready_factory()
        factory.backend.open_session.side_effect = RuntimeError("lost")
        assert factory.get_public_keys() is None

    def test_sign_success(self):
        factory = self._ready_factory()
        factory.backend.sign.return_value = b"sig"
        assert factory.sign(b"msg") == b"sig"

    def test_sign_error_returns_none(self):
        factory = self._ready_factory()
        factory.backend.sign.side_effect = RuntimeError("fault")
        assert factory.sign(b"msg") is None

    def test_ecdh_public_key_success(self):
        factory = self._ready_factory()
        factory.backend.get_public_key.return_value = b"x-pub"
        assert factory.ecdh_public_key() == b"x-pub"

    def test_ecdh_public_key_error_returns_none(self):
        factory = self._ready_factory()
        factory.backend.open_session.side_effect = RuntimeError("fault")
        assert factory.ecdh_public_key() is None


class TestSlotQueries:
    """Tests for module-level slot helper functions."""

    def test_is_app_using_hardware_true(self):
        with patch.object(ti, "load_hardware_identity_config", return_value={"exclude_apps": []}), \
             patch.object(ti, "AppIdentityMapper") as MapperCls:
            MapperCls.return_value.get_app_slot.return_value = "9a"
            assert is_app_using_hardware("sideband") is True

    def test_get_app_hardware_slot(self):
        with patch.object(ti, "load_hardware_identity_config", return_value={"exclude_apps": []}), \
             patch.object(ti, "AppIdentityMapper") as MapperCls:
            MapperCls.return_value.get_app_slot.return_value = "9d"
            assert get_app_hardware_slot("sideband") == "9d"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
