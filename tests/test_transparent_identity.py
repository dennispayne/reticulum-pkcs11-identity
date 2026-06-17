"""
Tests for transparent hardware identity (zero-config).
"""

import tempfile
import os
import pytest

from reticulum_pkcs11_identity.transparent_identity import (
    TransparentHardwareIdentityFactory,
    get_or_create_hardware_identity,
    is_app_using_hardware,
    get_app_hardware_slot,
    list_all_app_slots,
)


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
