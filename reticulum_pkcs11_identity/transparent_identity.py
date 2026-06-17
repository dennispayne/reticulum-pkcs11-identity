"""
Transparent hardware identity for multi-app Reticulum flows.

ZERO-CONFIG PRINCIPLE: Apps make zero changes. This module provides
transparent hardware-backing that works automatically when:
  1. A YubiKey is plugged in
  2. PIN is configured (via env var or config file)
  3. App calls get_or_create_hardware_identity()

If hardware isn't available, gracefully falls back to software identity.
No exceptions, no drama.
"""

import os
from typing import Optional

from .app_identity import AppIdentityMapper
from .backend_piv import PKCS11PIVBackend
from .config import PKCS11Config, load_hardware_identity_config
from .pkcs11_provider import get_default_provider
from .exceptions import PKCS11ProviderNotFoundError


class TransparentHardwareIdentityFactory:
    """
    Transparent factory for hardware-backed identities (zero-config).
    
    This is designed for apps that just want to call one function and either
    get a hardware identity or None (meaning "use software as usual").
    """

    def __init__(self, app_name: str):
        """
        Initialize factory.

        Args:
            app_name: App identifier (e.g., "sideband", "meshchat")
        """
        self.app_name = app_name
        self.config = PKCS11Config()
        
        # Load exclude_apps from hardware_identity config
        hw_config = load_hardware_identity_config()
        exclude_apps = hw_config.get("exclude_apps", [])
        
        self.mapper = AppIdentityMapper(exclude_apps=exclude_apps)
        self.backend: Optional[PKCS11PIVBackend] = None
        self.slot: Optional[str] = None
        self._hardware_available = False

    def try_setup_hardware(self) -> bool:
        """
        Attempt to set up hardware identity.

        Returns:
            True if hardware is ready, False if should fall back to software

        This never raises exceptions. Any error silently returns False.
        """
        try:
            # Check if app is excluded
            if self.mapper.is_app_excluded(self.app_name):
                return False
            
            # Get PIN - must be available
            pin = self.config.get_pin()
            if not pin:
                return False

            # Try to get provider - may not be available
            try:
                provider = self.config.get_provider()
                if provider == "auto":
                    provider = get_default_provider()
            except PKCS11ProviderNotFoundError:
                # No provider found - that's OK, we'll use software
                return False

            # Initialize backend
            self.backend = PKCS11PIVBackend(provider_path=provider, pin=pin)

            # Get or allocate slot
            self.slot = self.mapper.get_app_slot(self.app_name)
            if not self.slot:
                self.slot = self.mapper.allocate_slot_for_app(self.app_name)

            # If allocation returned None (app was excluded), fall back
            if not self.slot:
                return False

            # Verify we can open a session
            session = self.backend.open_session(self.slot)

            # All good - hardware is available
            self._hardware_available = True
            return True

        except Exception:
            # Any error at all - silently fall back to software
            self._hardware_available = False
            return False

    def is_hardware_available(self) -> bool:
        """Check if hardware identity is available."""
        return self._hardware_available

    def get_public_keys(self) -> Optional[tuple[bytes, bytes]]:
        """
        Get Ed25519 and X25519 public keys from hardware.

        Returns:
            (ed25519_pub, x25519_pub) or None if not available
        """
        if not self._hardware_available or not self.backend or not self.slot:
            return None

        try:
            session = self.backend.open_session(self.slot)
            ed_pub = self.backend.get_public_key(session, "sign")
            x_pub = self.backend.get_public_key(session, "enc")
            return (ed_pub, x_pub)
        except:
            return None

    def sign(self, message: bytes) -> Optional[bytes]:
        """
        Sign message using hardware key.

        Returns:
            Signature bytes or None if hardware not available
        """
        if not self._hardware_available or not self.backend or not self.slot:
            return None

        try:
            session = self.backend.open_session(self.slot)
            return self.backend.sign(session, message)
        except:
            return None

    def ecdh_public_key(self) -> Optional[bytes]:
        """
        Get X25519 public key for key exchange.

        Returns:
            Public key bytes or None if hardware not available
        """
        if not self._hardware_available or not self.backend or not self.slot:
            return None

        try:
            session = self.backend.open_session(self.slot)
            return self.backend.get_public_key(session, "enc")
        except:
            return None


def get_or_create_hardware_identity(app_name: str) -> Optional[TransparentHardwareIdentityFactory]:
    """
    Get or create hardware identity for an app.

    ZERO-CONFIG: This is designed to be called by apps with NO other setup.
    It silently handles all configuration, slot allocation, and key generation.

    Args:
        app_name: Application identifier

    Returns:
        TransparentHardwareIdentityFactory if hardware is ready, None otherwise

    Usage (for app developers - zero changes needed):
        from reticulum_pkcs11_identity import get_or_create_hardware_identity

        # Try to get hardware identity
        hw_identity = get_or_create_hardware_identity("sideband")
        
        if hw_identity:
            # Hardware is available - use it
            ed_public, x_public = hw_identity.get_public_keys()
            # Create RNS.Identity with these public keys
            identity = my_create_rns_identity_with_keys(ed_public, x_public)
            # Override sign and decrypt to use hardware
            identity.sign = hw_identity.sign
        else:
            # Hardware not available - use software as usual
            identity = my_create_software_identity()
    """
    factory = TransparentHardwareIdentityFactory(app_name)
    if factory.try_setup_hardware():
        return factory
    return None


def is_app_using_hardware(app_name: str) -> bool:
    """
    Check if an app is currently mapped to a hardware slot.

    Returns:
        True if app has a mapped slot, False otherwise
    """
    hw_config = load_hardware_identity_config()
    exclude_apps = hw_config.get("exclude_apps", [])
    mapper = AppIdentityMapper(exclude_apps=exclude_apps)
    return mapper.get_app_slot(app_name) is not None


def get_app_hardware_slot(app_name: str) -> Optional[str]:
    """
    Get which PIV slot an app is using.

    Returns:
        Slot ID ("9a", "9c", "9d", "9e") or None if app not mapped
    """
    hw_config = load_hardware_identity_config()
    exclude_apps = hw_config.get("exclude_apps", [])
    mapper = AppIdentityMapper(exclude_apps=exclude_apps)
    return mapper.get_app_slot(app_name)


def list_all_app_slots() -> dict[str, str]:
    """
    Get all app-to-slot mappings on this device.

    Returns:
        Dict of {app_name: slot_id}
    """
    hw_config = load_hardware_identity_config()
    exclude_apps = hw_config.get("exclude_apps", [])
    mapper = AppIdentityMapper(exclude_apps=exclude_apps)
    result = {}
    for slot in ["9a", "9c", "9d", "9e"]:
        apps = mapper.get_slot_apps(slot)
        for app in apps:
            result[app] = slot
    return result
