"""
Transparent integration with RNS.Identity.

When an app creates an RNS.Identity, this module can intercept the creation
and transparently substitute hardware keys if available.

**No app changes needed** (when integration is enabled).

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


def _get_hardware_keys_for_app(app_name: str, backend=None) -> Optional[tuple[bytes, bytes]]:
    """
    Get hardware public keys for an app.

    :param app_name: Application name
    :param backend: PKCS11Backend instance (required). If None, returns None.
    :returns:
        (ed25519_public, x25519_public) if available, None otherwise
    """
    if backend is None:
        return None
    
    try:
        mapper = AppIdentityMapper()
        slot = mapper.get_app_slot(app_name)
        
        if not slot:
            return None

        # Get public keys directly from backend
        sign_key_label = f"{app_name}-sign"
        enc_key_label = f"{app_name}-enc"
        
        ed_pub = backend.get_public_key_bytes(
            key_label=sign_key_label,
            key_id=None,
        )
        x_pub = backend.get_public_key_bytes(
            key_label=enc_key_label,
            key_id=None,
        )
        
        return (ed_pub, x_pub)

    except Exception:
        return None


def enable_hardware_identity_injection(backend=None) -> None:
    """
    Enable transparent hardware identity injection (deprecated).

    This function is provided for backward compatibility but is deprecated.
    Transparent injection without explicit backend setup is no longer supported.

    For new code, use:
    - make_app_hardware_identity_class() for explicit multi-app identities
    - make_lxmf_identity_class() for LXMF identities
    
    Both require a PKCS11Backend instance to be passed explicitly.

    :param backend: PKCS11Backend instance (optional, for future use).
    """
    try:
        import RNS
    except ImportError:
        # RNS not installed - skip injection
        return

    if backend is None:
        # Without explicit backend, transparent injection is not possible
        RNS.log(
            "Hardware identity injection requires explicit backend setup; "
            "use make_app_hardware_identity_class() or make_lxmf_identity_class() instead",
            RNS.LOG_DEBUG,
        )
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
            hardware_keys = _get_hardware_keys_for_app(app_name, backend=backend)

        if hardware_keys:
            # Hardware keys available - inject them
            ed_pub, x_pub = hardware_keys
            
            # Call original init (will create software keys)
            original_init(self, create_keys=create_keys)
            
            # Override with hardware keys
            self.pub_bytes = x_pub
            self.sig_pub_bytes = ed_pub
            
            slot = AppIdentityMapper().get_app_slot(app_name)
            
            if slot:
                # Store hardware info for sign() override
                self._hw_backend = backend
                self._hw_slot = slot
                self._hw_app_name = app_name
                
                # Override sign() method
                original_sign = self.sign
                
                def hw_sign(message: bytes) -> bytes:
                    """Sign using hardware key."""
                    try:
                        sign_key_label = f"{app_name}-sign"
                        return self._hw_backend.sign(
                            message,
                            key_label=sign_key_label,
                            key_id=None,
                        )
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
