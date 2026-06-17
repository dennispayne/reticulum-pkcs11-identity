"""
Configuration management for PKCS#11 hardware identities.

Handles PIN, provider selection, token selection, and app-to-slot mapping.
Config stored in ~/.config/reticulum/pkcs11_identity.conf
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any

from .exceptions import PKCS11ConfigError


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
            "pin": None,
            "pin_env": "RNS_PKCS11_PIN",  # Fallback to env var
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
        Get PIN.
        
        Tries in order:
        1. Configured PIN
        2. Environment variable (RNS_PKCS11_PIN or custom)
        3. None
        """
        # First try configured PIN
        pin = self.get("pin")
        if pin:
            return pin
        
        # Try environment variable
        pin_env = self.get("pin_env", "RNS_PKCS11_PIN")
        if pin_env:
            pin = os.environ.get(pin_env)
            if pin:
                return pin
        
        return None

    def set_pin(self, pin: str, save: bool = True) -> None:
        """
        Set PIN.
        
        Args:
            pin: PIN string
            save: If False, only store in memory (not persisted to disk)
        """
        self._data["pin"] = pin
        if save:
            self._save()

    def get_pin_env_var(self) -> str:
        """Get name of environment variable for PIN fallback."""
        return self.get("pin_env", "RNS_PKCS11_PIN")

    def set_pin_env_var(self, env_var: str) -> None:
        """Set environment variable name for PIN fallback."""
        self.set("pin_env", env_var)

    def validate(self) -> None:
        """
        Validate config is usable.
        
        Raises:
            PKCS11ConfigError: If config is invalid
        """
        # PIN must be available
        pin = self.get_pin()
        if not pin:
            raise PKCS11ConfigError(
                "PIN not configured. Set 'pin' in config or RNS_PKCS11_PIN env var."
            )
        
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
