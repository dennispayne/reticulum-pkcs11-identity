"""
Transparent integration with RNS.Identity.

When an app creates an RNS.Identity, this module can intercept the creation
and transparently substitute hardware keys if available.

**No app changes needed** (when integration is enabled).

Integration strategy:
  1. At module import time, check if hardware_identity is enabled in config
  2. If enabled: initialize PKCS#11 backend and monkey-patch RNS.Identity.__init__()
  3. When identity created: detect app name and inject hardware keys if available
  4. If no hardware available: create software identity as usual (app unaware)

Module imports auto-initialize the patch based on config, but manual
enable_hardware_identity_injection() is still available for explicit control.
"""

import logging
import os
import inspect
from typing import Optional

from .app_identity import AppIdentityMapper
from .config import load_hardware_identity_config

logger = logging.getLogger(__name__)

# Global state for the auto-initialized backend
_auto_initialized_backend = None
_patch_installed = False


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


def _get_hardware_keys_for_app(app_name: str, backend=None, exclude_apps=None) -> Optional[tuple[bytes, bytes]]:
    """
    Get hardware public keys for an app.

    :param app_name: Application name
    :param backend: PKCS11Backend instance (required). If None, returns None.
    :param exclude_apps: List of app names to exclude from hardware backing
    :returns:
        (ed25519_public, x25519_public) if available, None otherwise
    """
    if backend is None:
        return None
    
    try:
        mapper = AppIdentityMapper(exclude_apps=exclude_apps or [])
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


def _build_hardware_identity_for_app(app_name, backend=None, exclude_apps=None):
    """Build a token-backed ``HardwareIdentity`` for *app_name*, or ``None``.

    Returns ``None`` (so the caller falls back to a software identity) when no
    backend is available, the app is excluded, the app has no mapped slot, or
    its keys are not present on the token. Never raises.
    """
    if backend is None:
        return None
    try:
        mapper = AppIdentityMapper(exclude_apps=exclude_apps or [])
        slot = mapper.get_app_slot(app_name)
        if not slot:
            return None
        # Imported lazily to avoid a circular import at module load time.
        from .identity import create_app_hardware_identity

        return create_app_hardware_identity(app_name, backend=backend, slot=slot)
    except Exception as exc:
        logger.debug(f"No hardware identity available for app '{app_name}': {exc}")
        return None


def _bind_hardware_identity(identity, hw_identity, app_name) -> None:
    """Turn a plain ``RNS.Identity`` into a token-backed one.

    Adopts *hw_identity*'s public material and routes the private-key
    operations (``sign``/``decrypt``) to it, so the private key only ever lives
    on the token. No software private key is retained, and the destination hash
    is taken from the hardware identity so it matches the advertised keys.
    """
    identity.pub = hw_identity.pub
    identity.pub_bytes = hw_identity.pub_bytes
    identity.sig_pub = hw_identity.sig_pub
    identity.sig_pub_bytes = hw_identity.sig_pub_bytes

    # ``prv`` is a truthy token-resident marker (it lets RNS generate delivery
    # proofs); the real X25519 key never leaves the token. ``prv_bytes`` stays
    # ``None`` so the identity correctly reports it holds no in-memory key.
    identity.prv = hw_identity.prv
    identity.prv_bytes = None
    identity.sig_prv = hw_identity.sig_prv
    identity.sig_prv_bytes = None

    identity.hash = hw_identity.hash
    identity.hexhash = hw_identity.hexhash

    # Route every private-key operation to the token. There is deliberately no
    # software fallback: a software signature would not verify against the
    # advertised hardware key, and the hardware key cannot be reconstructed.
    identity.sign = hw_identity.sign
    identity.decrypt = hw_identity.decrypt
    identity.get_private_key = hw_identity.get_private_key

    identity._is_hardware_backed = True
    identity._hw_app_name = app_name
    identity._hw_slot = getattr(hw_identity, "_slot", None)
    identity._hw_identity = hw_identity


def _install_monkey_patch(backend, exclude_apps=None) -> bool:
    """
    Install the monkey-patch on RNS.Identity.
    
    :param backend: PKCS11Backend instance to use for hardware operations
    :param exclude_apps: List of app names to exclude from hardware backing
    :returns: True if patch installed successfully, False otherwise
    """
    try:
        import RNS
    except ImportError:
        logger.debug("RNS not installed - skipping hardware identity injection patch")
        return False

    # Check if already patched
    global _patch_installed
    if _patch_installed:
        return True

    # Save original __init__
    original_init = RNS.Identity.__init__

    def patched_init(self, create_keys: bool = True):
        """Patched ``RNS.Identity.__init__`` with transparent hardware injection.

        When a token-backed identity is available for the detected app, the new
        instance is turned into a hardware identity: its public keys, hash and
        private-key operations are taken from a real ``HardwareIdentity`` so the
        private key never exists in software. Otherwise it initialises as a
        normal software identity.
        """
        app_name = _detect_app_name()
        hw_identity = None
        if app_name:
            hw_identity = _build_hardware_identity_for_app(
                app_name, backend=backend, exclude_apps=exclude_apps
            )

        if hw_identity is not None:
            # Initialise the RNS.Identity scaffolding WITHOUT generating any
            # software keys, then adopt the token-backed material/operations.
            original_init(self, create_keys=False)
            _bind_hardware_identity(self, hw_identity, app_name)
        else:
            # No hardware available - behave like a normal software identity.
            original_init(self, create_keys=create_keys)

    # Apply monkey patch
    RNS.Identity.__init__ = patched_init
    _patch_installed = True
    return True


def _auto_initialize() -> None:
    """
    Auto-initialize hardware identity injection at module import time.
    
    This is called once when the module is imported. It:
    1. Loads config from ~/.config/reticulum/config [hardware_identity] section
    2. If enabled and not in exclude_apps:
       - Initializes PKCS#11 backend
       - Installs monkey patch
       - Logs info message
    3. If disabled or not configured:
       - Logs info message
    4. If enabled but provider unavailable:
       - Logs warning
       - Does not install patch (falls back to software identities)
    """
    global _auto_initialized_backend, _patch_installed
    
    try:
        # Load config
        config = load_hardware_identity_config()
        exclude_apps = config.get("exclude_apps", [])
        
        if not config.get("enabled"):
            logger.info("Hardware identity injection disabled or not configured")
            return
        
        # Check if this app is in the exclude list
        app_name = _detect_app_name()
        if app_name and app_name in exclude_apps:
            logger.info(f"Hardware identity injection disabled for excluded app: {app_name}")
            return
        
        # Try to initialize backend
        try:
            from .backend import PKCS11Backend
            
            # Try to create backend with config settings
            provider = config.get("provider")
            token_label = config.get("token_label")
            
            # If provider not specified, try auto-detection
            if not provider:
                detected = config.get("detected_providers", {})
                if detected.get("auto_selected"):
                    provider = detected.get("auto_selected")
            
            if provider:
                # Create backend - requires either token_label or slot_id
                # If neither configured, use a default slot
                token_label = config.get("token_label")
                backend = PKCS11Backend(
                    module_path=provider,
                    token_label=token_label,
                )
                _auto_initialized_backend = backend
                
                # Install the monkey patch with exclude_apps
                if _install_monkey_patch(backend, exclude_apps=exclude_apps):
                    logger.info("Hardware identity injection enabled")
                    return
            else:
                logger.warning(
                    "Hardware identity injection requested but no PKCS#11 provider configured or detected"
                )
                return
        
        except ImportError:
            logger.warning("PKCS#11 backend not available - falling back to software identities")
            return
        except Exception as e:
            logger.warning(f"Hardware identity injection requested but provider unavailable: {e}")
            return
    
    except Exception as e:
        logger.warning(f"Error during hardware identity auto-initialization: {e}")
        return


def enable_hardware_identity_injection(backend=None) -> None:
    """
    Manually enable transparent hardware identity injection.

    This function allows explicit control over hardware identity injection,
    overriding the auto-initialized state from config.

    For most users, the auto-initialization at module import handles this.
    Use this function only if you need explicit control or a non-standard
    backend setup.

    Args:
        backend: PKCS11Backend instance. If None, uses the auto-initialized backend.
                If no backend is available, logs an info message and returns.
    """
    global _auto_initialized_backend
    
    if backend is None:
        backend = _auto_initialized_backend
    
    if backend is None:
        try:
            import RNS
            RNS.log(
                "Hardware identity injection requires a PKCS#11 backend; "
                "check config [hardware_identity] section or pass backend explicitly",
                RNS.LOG_INFO,
            )
        except ImportError:
            logger.info("RNS not available for hardware identity injection")
        return

    # Install patch with provided/auto backend
    _install_monkey_patch(backend)


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


# Auto-initialize hardware identity injection at module import time
_auto_initialize()
