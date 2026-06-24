"""
Configuration management for PKCS#11 hardware identities.

Handles PIN, provider selection, and token selection. Config stored in
~/.reticulum/config [hardware_identity] section. The experimental
multi-identity feature adds per-app slot mapping on top of this; see
``reticulum_pkcs11_identity.experimental``.
"""

import configparser
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any

from .exceptions import PKCS11ConfigError

logger = logging.getLogger(__name__)


def load_hardware_identity_config(reticulum_config_path: str | None = None) -> Dict[str, Any]:
    """
    Load hardware_identity configuration from Reticulum config file.
    
    Args:
        reticulum_config_path: Path to Reticulum config file.
                              Defaults to ~/.reticulum/config
    
    Returns:
        Config dict with keys:
        {
            "enabled": bool,
            "provider": Optional[str],
            "token_label": Optional[str],
            "exclude_apps": List[str],
            "detected_providers": Dict[str, Any]
        }
    """
    if reticulum_config_path is None:
        reticulum_config_path = os.path.expanduser("~/.reticulum/config")
    
    config_path = Path(reticulum_config_path)
    config = {
        "enabled": False,
        "provider": None,
        "token_label": None,
        "exclude_apps": [],
        "detected_providers": {},
        # Experimental feature gates (default OFF). The production model is a
        # single hardware identity used across apps via RNS aspects; the
        # multi-identity / per-app-slot machinery is opt-in and lives under
        # ``reticulum_pkcs11_identity.experimental``.
        "experimental_features": False,
        "multi_identity": False,
    }
    
    if not config_path.exists():
        logger.debug(f"Reticulum config file not found: {config_path}")
        return config
    
    try:
        parser = configparser.ConfigParser()
        parser.read(config_path)
        
        if not parser.has_section("hardware_identity"):
            logger.debug("No [hardware_identity] section in Reticulum config")
            return config
        
        # Parse enabled flag
        if parser.has_option("hardware_identity", "enabled"):
            enabled_str = parser.get("hardware_identity", "enabled").lower()
            config["enabled"] = enabled_str in ("true", "yes", "1", "on")

        # Parse experimental feature gates. Both the master switch
        # (experimental_features) and the specific flag (multi_identity) must be
        # truthy for the multi-identity feature to activate.
        _truthy = ("true", "yes", "1", "on")
        if parser.has_option("hardware_identity", "experimental_features"):
            config["experimental_features"] = (
                parser.get("hardware_identity", "experimental_features").strip().lower() in _truthy
            )
        if parser.has_option("hardware_identity", "multi_identity"):
            config["multi_identity"] = (
                parser.get("hardware_identity", "multi_identity").strip().lower() in _truthy
            )
        
        # Parse provider
        if parser.has_option("hardware_identity", "provider"):
            provider = parser.get("hardware_identity", "provider").strip()
            if provider:
                config["provider"] = provider
                # Verify provider exists
                provider_path = Path(provider)
                if not provider_path.exists() and not os.path.isfile(provider):
                    # Provider might be a name like "libykcs11", "opensc-pkcs11", "softhsm2"
                    if provider not in ("libykcs11", "opensc-pkcs11", "softhsm2"):
                        logger.warning(
                            f"Configured provider not found: {provider}. "
                            "Will attempt to detect available providers."
                        )
        
        # Parse token_label
        if parser.has_option("hardware_identity", "token_label"):
            token_label = parser.get("hardware_identity", "token_label").strip()
            if token_label:
                config["token_label"] = token_label
        
        # Parse exclude_apps (comma-separated or as INI list)
        if parser.has_option("hardware_identity", "exclude_apps"):
            exclude_str = parser.get("hardware_identity", "exclude_apps").strip()
            if exclude_str:
                # Handle comma-separated or newline-separated values
                apps = []
                for item in exclude_str.split(","):
                    item = item.strip()
                    if item:
                        apps.append(item)
                # Also handle multiline format (each on new line with indentation)
                if not apps and "\n" in exclude_str:
                    for line in exclude_str.split("\n"):
                        line = line.strip()
                        if line:
                            apps.append(line)
                config["exclude_apps"] = apps
        
        # If enabled and provider not specified, detect available providers
        if config["enabled"] and not config["provider"]:
            try:
                from .discovery import discover_pkcs11_modules
                discovered = discover_pkcs11_modules()
                if discovered:
                    config["detected_providers"] = {
                        "available": discovered,
                        "auto_selected": discovered[0] if discovered else None
                    }
                    logger.info(f"Auto-detected PKCS#11 providers: {discovered}")
            except Exception as e:
                logger.warning(f"Failed to auto-detect PKCS#11 providers: {e}")
        
        logger.debug(f"Loaded hardware_identity config: enabled={config['enabled']}, "
                    f"provider={config['provider']}, token_label={config['token_label']}, "
                    f"exclude_apps={config['exclude_apps']}")
        
    except Exception as e:
        logger.warning(f"Failed to parse [hardware_identity] section: {e}")
    
    return config


def multi_identity_enabled(config: Dict[str, Any] | None = None) -> bool:
    """Return True only if the experimental multi-identity feature is enabled.

    Requires BOTH ``experimental_features`` and ``multi_identity`` to be set in
    the ``[hardware_identity]`` config section. The production default is a
    single hardware identity shared across apps via RNS aspects, so this returns
    False unless the user has explicitly opted in.

    :param config: A config dict from :func:`load_hardware_identity_config`.
        Loaded automatically when omitted.
    """
    if config is None:
        config = load_hardware_identity_config()
    return bool(config.get("experimental_features")) and bool(config.get("multi_identity"))


class PKCS11Config:
    """Configuration for PKCS#11 provider and hardware identity setup."""

    def __init__(self, config_file: str | None = None):
        """
        Initialize config.

        Args:
            config_file: Path to config file. Defaults to ~/.config/reticulum/pkcs11_identity.conf
        """
        if config_file is None:
            config_file = os.path.expanduser("~/.config/reticulum/pkcs11_identity.conf")
        
        self.config_file = Path(config_file)
        self._data: Dict[str, Any] = {
            "provider": "auto",  # auto-detect
            "token_label": None,  # Will be detected
            "pin_env": "RNS_PKCS11_PIN",  # Name of an env var to read the PIN from
        }
        
        # Load from file if it exists
        self._load()

    def _load(self) -> None:
        """Load configuration from file."""
        if not self.config_file.exists():
            return
        
        try:
            with open(self.config_file, "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    
                    if "=" not in line:
                        continue
                    
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]

                    # Never honor a PIN written into the config file: storing a
                    # PIN defeats its purpose. The PIN is collected at session
                    # start (token PIN pad or interactive prompt) instead.
                    if key == "pin":
                        logger.warning(
                            "Ignoring 'pin' in %s: PINs are never read from a config file.",
                            self.config_file,
                        )
                        continue

                    self._data[key] = value
        except Exception as e:
            raise PKCS11ConfigError(f"Failed to load config: {e}") from e

    def _save(self) -> None:
        """Save configuration to file."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, "w") as f:
                f.write("# PKCS#11 Hardware Identity Configuration\n")
                f.write("# Auto-generated - edit carefully\n\n")
                
                # Write each key-value pair
                for key in sorted(self._data.keys()):
                    if key == "pin":
                        # A PIN must never be persisted to disk.
                        continue
                    value = self._data[key]
                    if value is None:
                        continue
                    
                    # Quote string values
                    if isinstance(value, str):
                        f.write(f'{key} = "{value}"\n')
                    else:
                        f.write(f'{key} = {value}\n')
        except Exception as e:
            raise PKCS11ConfigError(f"Failed to save config: {e}") from e

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value."""
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set config value and persist."""
        self._data[key] = value
        self._save()

    def get_provider(self) -> Optional[str]:
        """Get configured PKCS#11 provider."""
        return self.get("provider")

    def set_provider(self, provider_path: str) -> None:
        """Set PKCS#11 provider."""
        self.set("provider", provider_path)

    def get_token_label(self) -> Optional[str]:
        """Get configured token label (e.g., "YubiKey PIV #12345")."""
        return self.get("token_label")

    def set_token_label(self, label: str) -> None:
        """Set token label to use."""
        self.set("token_label", label)

    def get_pin(self) -> Optional[str]:
        """
        Get a PIN for the current process, if one is available without prompting.

        The PIN is **never** read from the config file. Returns, in order:

        1. A PIN set in memory this process via :meth:`set_pin`.
        2. The environment variable named by ``pin_env`` (default
           ``RNS_PKCS11_PIN``), for non-interactive/automation use.
        3. ``None`` -- the caller should prompt at session start or rely on the
           token's own PIN entry.
        """
        # In-memory PIN (this process only -- never loaded from disk).
        pin = self._data.get("pin")
        if pin:
            return pin

        # Environment variable (not a config file).
        pin_env = self.get("pin_env", "RNS_PKCS11_PIN")
        if pin_env:
            pin = os.environ.get(pin_env)
            if pin:
                return pin

        return None

    def set_pin(self, pin: str, save: bool = False) -> None:
        """
        Hold a PIN in memory for the current process only.

        The PIN is **never** written to disk, regardless of *save*: persisting a
        PIN would defeat its purpose. *save* is retained only for backward
        compatibility and is ignored.
        """
        self._data["pin"] = pin

    def get_pin_env_var(self) -> str:
        """Get name of environment variable for PIN fallback."""
        return self.get("pin_env", "RNS_PKCS11_PIN")

    def set_pin_env_var(self, env_var: str) -> None:
        """Set environment variable name for PIN fallback."""
        self.set("pin_env", env_var)

    def validate(self) -> None:
        """
        Validate config is usable.

        The PIN is intentionally **not** required here: it is collected at
        session start (token PIN pad or interactive prompt), never stored in
        configuration.

        Raises:
            PKCS11ConfigError: If config is invalid
        """
        # Provider should be set (can be "auto")
        provider = self.get_provider()
        if not provider:
            raise PKCS11ConfigError("Provider not configured.")

    def __repr__(self) -> str:
        """String representation."""
        lines = ["PKCS11Config:"]
        for key in sorted(self._data.keys()):
            value = self._data[key]
            # Mask PIN
            if key == "pin" and value:
                value = "***"
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)


class ConfigBuilder:
    """Fluent builder for PKCS#11 configuration."""

    def __init__(self):
        """Initialize builder."""
        self.config = PKCS11Config()

    def with_provider(self, provider_path: str) -> "ConfigBuilder":
        """Set provider."""
        self.config.set_provider(provider_path)
        return self

    def with_token_label(self, label: str) -> "ConfigBuilder":
        """Set token label."""
        self.config.set_token_label(label)
        return self

    def with_pin(self, pin: str, save: bool = False) -> "ConfigBuilder":
        """Set PIN (in-memory by default)."""
        self.config.set_pin(pin, save=save)
        return self

    def with_pin_env_var(self, env_var: str) -> "ConfigBuilder":
        """Set PIN environment variable."""
        self.config.set_pin_env_var(env_var)
        return self

    def build(self) -> PKCS11Config:
        """Return configured object."""
        return self.config
