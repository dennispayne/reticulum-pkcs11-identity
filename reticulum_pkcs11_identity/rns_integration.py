"""
Transparent integration with RNS.Identity.

When an app creates an RNS.Identity, this module intercepts the creation
and transparently substitutes hardware keys if available.

**No app changes needed.**

Integration strategy:
  1. Monkey-patch RNS.Identity.__init__() to intercept identity creation
  2. Detect app name (from calling code or env var)
  3. Check if app has hardware slot mapped
  4. If yes: inject hardware public keys, override sign() method
  5. If no: create software identity as usual (app unaware)
"""

import os
import sys
import inspect
from typing import Optional

from .app_identity import AppIdentityMapper
from .backend_piv import PKCS11PIVBackend
from .session_manager import get_session_manager


def _detect_app_name() -> Optional[str]:
    """
    Detect calling app name from call stack or environment.

    Returns:
        App name (e.g., "sideband") or None
    """
    # First try environment variable
    app_name = os.environ.get("RNS_APP_NAME")
    if app_name:
        return app_name

    # Try to detect from calling module
    try:
        # Walk up the call stack to find the app module
        frame = inspect.currentframe()
        if frame is None:
            return None

        # Skip frames from this module
        while frame:
            module_name = frame.f_globals.get("__name__", "")
            
            # Skip this module and RNS internals
            if "reticulum_pkcs11_identity" in module_name or "RNS" in module_name:
                frame = frame.f_back
                continue

            # Found app module - extract app name from it
            if module_name and "." in module_name:
                # e.g., "sideband.main" → "sideband"
                return module_name.split(".")[0]
            elif module_name:
                return module_name

            frame = frame.f_back

    except Exception:
        pass

    return None


def _get_hardware_keys_for_app(app_name: str) -> Optional[tuple[bytes, bytes]]:
    """
    Get hardware public keys for an app.

    Returns:
        (ed25519_public, x25519_public) if available, None otherwise
    """
    try:
        mapper = AppIdentityMapper()
        slot = mapper.get_app_slot(app_name)
        
        if not slot:
            return None

        # Get session manager
        manager = get_session_manager()
        if not manager.is_ready():
            return None

        backend = manager.get_backend()
        if not backend:
            return None

        # Open session and get keys
        session = backend.open_session(slot)
        ed_pub = backend.get_public_key(session, "sign")
        x_pub = backend.get_public_key(session, "enc")
        
        return (ed_pub, x_pub)

    except Exception:
        return None


def enable_hardware_identity_injection() -> None:
    """
    Enable transparent hardware identity injection.

    Call this once at node startup (after session_manager.initialize()).
    This monkey-patches RNS.Identity.__init__() to intercept identity creation.
    """
    try:
        import RNS
    except ImportError:
        # RNS not installed - skip injection
        return

    # Save original __init__
    original_init = RNS.Identity.__init__

    def patched_init(self, create_keys: bool = True):
        """
        Patched RNS.Identity.__init__() with transparent hardware injection.
        """
        # Try to detect app and get hardware keys
        app_name = _detect_app_name()
        hardware_keys = None

        if app_name:
            hardware_keys = _get_hardware_keys_for_app(app_name)

        if hardware_keys:
            # Hardware keys available - inject them
            ed_pub, x_pub = hardware_keys
            
            # Call original init (will create software keys)
            original_init(self, create_keys=create_keys)
            
            # Override with hardware keys
            self.pub_bytes = x_pub
            self.sig_pub_bytes = ed_pub
            
            # Get backend for signing
            backend = get_session_manager().get_backend()
            if backend:
                slot = AppIdentityMapper().get_app_slot(app_name)
                
                if slot and backend:
                    # Store hardware info for sign() override
                    self._hw_backend = backend
                    self._hw_slot = slot
                    self._hw_app_name = app_name
                    
                    # Override sign() method
                    original_sign = self.sign
                    
                    def hw_sign(message: bytes) -> bytes:
                        """Sign using hardware key."""
                        try:
                            session = self._hw_backend.open_session(self._hw_slot)
                            return self._hw_backend.sign(session, message)
                        except Exception:
                            # Fallback to software signing
                            return original_sign(message)
                    
                    self.sign = hw_sign
                    
                    # Mark as hardware-backed
                    self._is_hardware_backed = True
        else:
            # Hardware not available - use software identity as usual
            original_init(self, create_keys=create_keys)

    # Apply monkey patch
    RNS.Identity.__init__ = patched_init


def is_identity_hardware_backed(identity) -> bool:
    """
    Check if an identity is hardware-backed.

    Args:
        identity: RNS.Identity instance

    Returns:
        True if identity uses hardware, False otherwise
    """
    return getattr(identity, "_is_hardware_backed", False)


def get_identity_app_name(identity) -> Optional[str]:
    """
    Get app name for a hardware-backed identity.

    Args:
        identity: RNS.Identity instance

    Returns:
        App name or None if not hardware-backed
    """
    return getattr(identity, "_hw_app_name", None)


def get_identity_slot(identity) -> Optional[str]:
    """
    Get PIV slot for a hardware-backed identity.

    Args:
        identity: RNS.Identity instance

    Returns:
        Slot ID ("9a", "9c", etc.) or None if not hardware-backed
    """
    return getattr(identity, "_hw_slot", None)
