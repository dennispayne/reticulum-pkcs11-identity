"""
App-to-PIV-slot mapper for multi-app identities.

Implements first-come-first-served slot allocation with persistence.
Each app gets its own (or shared) PIV slot, ensuring multiple apps
can have independent hardware-backed identities on the same YubiKey.

Mapping is keyed by identity filepath (canonical) with app_name as metadata.
Supports exclusion lists to prevent certain apps from using hardware.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any

from .exceptions import (
    AppNotMappedError,
    SlotAlreadyOccupiedError,
    SlotNotFoundError,
    PKCS11ConfigError,
)

logger = logging.getLogger(__name__)

# PIV slots in order of allocation priority
PIV_SLOTS = ["9a", "9c", "9d", "9e"]
PIV_SLOT_NAMES = {
    "9a": "AUTHENTICATION",
    "9c": "SIGNATURE",
    "9d": "KEY_MANAGEMENT",
    "9e": "CARD_AUTHENTICATION",
}


class AppIdentityMapper:
    """
    Maps identity filepaths to PIV slots with first-come-first-served allocation.

    Stores mapping persistently in ~/.config/reticulum/pkcs11_app_slots.json.
    
    Mapping format (JSON):
    {
        "/home/user/.reticulum/storage/identities/meshchat.identity": {
            "slot": "9C",
            "provider": "libykcs11",
            "app_name": "meshchat",
            "created": 1234567890
        }
    }
    """

    def __init__(self, config_dir: str | None = None, exclude_apps: list[str] | None = None):
        """
        Initialize mapper.

        Args:
            config_dir: Config directory. Defaults to ~/.config/reticulum/
            exclude_apps: List of app names to exclude from hardware backing
        """
        if config_dir is None:
            config_dir = os.path.expanduser("~/.config/reticulum")
        
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "pkcs11_app_slots.json"
        self.exclude_apps = set(exclude_apps or [])
        self._mapping = {}  # filepath -> {"slot": "9c", "app_name": "...", "created": ...}
        self._slot_apps = {}  # slot -> app_names (list, for sharing)
        
        # Load existing mapping
        self._load_mapping()

    def _load_mapping(self) -> None:
        """Load filepath->slot mapping from config file."""
        self._mapping.clear()
        self._slot_apps.clear()
        
        if not self.config_file.exists():
            return
        
        try:
            with open(self.config_file, "r") as f:
                data = json.load(f)
            
            if not isinstance(data, dict):
                logger.warning(f"Mapping file has invalid format (not a dict), rebuilding")
                return
            
            # Load mappings
            for filepath_key, mapping_info in data.items():
                if not isinstance(mapping_info, dict):
                    logger.warning(f"Skipping invalid mapping entry: {filepath_key}")
                    continue
                
                slot = mapping_info.get("slot")
                if not slot:
                    logger.warning(f"Skipping mapping with no slot: {filepath_key}")
                    continue
                
                # Store mapping
                self._mapping[filepath_key] = mapping_info
                
                # Track which apps use each slot
                if slot not in self._slot_apps:
                    self._slot_apps[slot] = []
                
                app_name = mapping_info.get("app_name", "unknown")
                if filepath_key not in self._slot_apps[slot]:
                    self._slot_apps[slot].append(app_name)
        
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse mapping file (corrupted JSON): {e}")
            logger.warning("Mapping will be rebuilt from scratch")
        except Exception as e:
            raise PKCS11ConfigError(f"Failed to load app mapping: {e}") from e

    def _save_mapping(self) -> None:
        """Save filepath->slot mapping to config file (JSON format)."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, "w") as f:
                json.dump(self._mapping, f, indent=2, sort_keys=True)
        except Exception as e:
            raise PKCS11ConfigError(f"Failed to save app mapping: {e}") from e

    def is_app_excluded(self, app_name: str) -> bool:
        """
        Check if an app is in the exclusion list.

        Args:
            app_name: Application name

        Returns:
            True if app should not use hardware backing
        """
        return app_name in self.exclude_apps

    def lookup_identity_for_filepath(self, filepath: str, backend=None) -> Optional[str]:
        """
        Look up PIV slot for an identity filepath.
        
        Uses two strategies:
        1. Check local mapping (fast path for single-node)
        2. If not found and backend provided, try cross-node discovery
           (matches public keys on token)

        Args:
            filepath: Full path to identity file (e.g., /home/user/.reticulum/storage/identities/meshchat.identity)
            backend: Optional PKCS11Backend for cross-node discovery

        Returns:
            Slot ID ("9a", "9c", "9d", "9e") or None if not mapped or app is excluded
        """
        # Strategy 1: Check if filepath exists in mapping (fast path)
        mapping_info = self._mapping.get(filepath)
        if mapping_info:
            # Check if app is excluded
            app_name = mapping_info.get("app_name")
            if app_name and self.is_app_excluded(app_name):
                logger.debug(f"App '{app_name}' is in exclusion list, returning None for filepath: {filepath}")
                return None
            
            return mapping_info.get("slot")
        
        # Strategy 2: Cross-node discovery via public key matching
        # (handles case where YubiKey was set up on different node)
        if backend and os.path.exists(filepath):
            logger.debug(f"Local mapping not found for {filepath}, attempting cross-node discovery")
            
            try:
                from .cross_node_discovery import discover_identity_on_token
                
                slot = discover_identity_on_token(filepath, backend)
                if slot is not None:
                    # Cache this mapping for next time
                    try:
                        # Extract app name from filepath for logging
                        app_name = os.path.basename(filepath).replace('.identity', '')
                        self.save_mapping(filepath, slot, app_name)
                        logger.info(f"Cached cross-node discovery: {filepath} → {slot}")
                    except Exception as e:
                        logger.warning(f"Could not cache discovered mapping: {e}")
                    
                    return slot
            except Exception as e:
                logger.debug(f"Cross-node discovery failed: {e}")
        
        return None

    def get_app_slot(self, app_name: str) -> Optional[str]:
        """
        Get PIV slot for an app by app name (deprecated, use filepath-based lookup).

        Args:
            app_name: Application name

        Returns:
            Slot ID ("9a", "9c", "9d", "9e") or None if not mapped
        
        Note: This is a backward-compatibility method. Prefer lookup_identity_for_filepath()
        """
        # Find first mapping with this app name
        for filepath, mapping_info in self._mapping.items():
            if mapping_info.get("app_name") == app_name:
                return self.lookup_identity_for_filepath(filepath)
        return None

    def get_slot_apps(self, slot: str) -> list[str]:
        """
        Get list of apps using a slot.

        Args:
            slot: Slot ID

        Returns:
            List of app names (possibly empty if slot unused)
        """
        return self._slot_apps.get(slot, [])

    def is_slot_available(self, slot: str) -> bool:
        """
        Check if a slot is available (unused).

        Args:
            slot: Slot ID

        Returns:
            True if slot is free, False if occupied
        """
        return slot not in self._slot_apps or len(self._slot_apps[slot]) == 0

    def allocate_slot_for_app(self, app_name: str, identity_filepath: str | None = None) -> Optional[str]:
        """
        Allocate first available slot for app (first-come-first-served).
        
        If app is in exclusion list, returns None (signals to use software identity).

        Args:
            app_name: Application name
            identity_filepath: Full path to identity file. If not provided, uses app_name 
                              (for backward compatibility only)

        Returns:
            Allocated slot ID ("9a", "9c", "9d", "9e") or None if excluded
        
        Raises:
            SlotNotFoundError: If all slots are full
        """
        # Check if app is excluded
        if self.is_app_excluded(app_name):
            logger.debug(f"App '{app_name}' is in exclusion list, skipping hardware allocation")
            return None
        
        # Use provided filepath or generate one from app name (backward compat)
        filepath = identity_filepath
        if not filepath:
            # For backward compatibility: construct filepath from app name
            default_storage = os.path.expanduser("~/.reticulum/storage/identities")
            filepath = os.path.join(default_storage, f"{app_name}.identity")
            logger.debug(f"No filepath provided for '{app_name}', using: {filepath}")
        
        # Check if this filepath already has a mapping
        if filepath in self._mapping:
            slot = self._mapping[filepath].get("slot")
            logger.debug(f"App '{app_name}' already has mapping at {filepath}: slot {slot}")
            return slot
        
        # Find first available slot
        for slot in PIV_SLOTS:
            if self.is_slot_available(slot):
                # Create new mapping
                self._mapping[filepath] = {
                    "slot": slot,
                    "app_name": app_name,
                    "created": int(time.time())
                }
                
                if slot not in self._slot_apps:
                    self._slot_apps[slot] = []
                self._slot_apps[slot].append(app_name)
                
                self._save_mapping()
                logger.info(f"Created {app_name} identity on slot PIV:{slot.upper()}")
                return slot
        
        raise SlotNotFoundError(
            f"No available PIV slots. All {len(PIV_SLOTS)} slots are in use."
        )

    def share_slot(self, slot: str, app_name: str, identity_filepath: str | None = None) -> None:
        """
        Make an app share a slot with existing app(s).

        Args:
            slot: Slot ID
            app_name: Application name to add to slot
            identity_filepath: Full path to identity file (optional)

        Raises:
            SlotNotFoundError: If slot doesn't exist
            SlotAlreadyOccupiedError: If app already has a different slot
        """
        if slot not in PIV_SLOTS:
            raise SlotNotFoundError(f"Invalid slot: {slot}")
        
        # Check if app is already on a different slot (by app_name)
        for filepath, mapping_info in self._mapping.items():
            if mapping_info.get("app_name") == app_name:
                current_slot = mapping_info.get("slot")
                if current_slot != slot:
                    raise SlotAlreadyOccupiedError(
                        f"App {app_name} already uses slot {current_slot}"
                    )
                # App already on this slot - return early
                return
        
        # Use provided filepath or generate one
        filepath = identity_filepath
        if not filepath:
            default_storage = os.path.expanduser("~/.reticulum/storage/identities")
            filepath = os.path.join(default_storage, f"{app_name}.identity")
        
        # Check if this specific filepath already mapped to different slot
        if filepath in self._mapping:
            current_slot = self._mapping[filepath].get("slot")
            if current_slot != slot:
                raise SlotAlreadyOccupiedError(
                    f"Filepath {filepath} already uses slot {current_slot}"
                )
            return  # Already mapped to this slot
        
        # Add app to slot
        if slot not in self._slot_apps:
            self._slot_apps[slot] = []
        
        self._mapping[filepath] = {
            "slot": slot,
            "app_name": app_name,
            "created": int(time.time())
        }
        self._slot_apps[slot].append(app_name)
        self._save_mapping()

    def unmap_app(self, app_name: str) -> Optional[str]:
        """
        Remove app from mapping (doesn't delete keys, just unmaps).

        Args:
            app_name: Application name

        Returns:
            Slot ID that was removed, or None if not mapped
        """
        # Find filepath for this app
        filepath_to_remove = None
        for filepath, mapping_info in self._mapping.items():
            if mapping_info.get("app_name") == app_name:
                filepath_to_remove = filepath
                break
        
        if not filepath_to_remove:
            return None
        
        slot = self._mapping[filepath_to_remove].get("slot")
        del self._mapping[filepath_to_remove]
        
        if slot in self._slot_apps:
            self._slot_apps[slot] = [
                a for a in self._slot_apps[slot] if a != app_name
            ]
            if not self._slot_apps[slot]:
                del self._slot_apps[slot]
        
        self._save_mapping()
        return slot

    def clear(self) -> None:
        """Clear all mappings and delete config file."""
        self._mapping.clear()
        self._slot_apps.clear()
        if self.config_file.exists():
            self.config_file.unlink()

    def __repr__(self) -> str:
        """String representation of current mapping."""
        lines = ["AppIdentityMapper:"]
        for slot in PIV_SLOTS:
            apps = self.get_slot_apps(slot)
            status = f"  {slot} ({PIV_SLOT_NAMES.get(slot, '?')}): "
            if apps:
                status += ", ".join(apps)
            else:
                status += "[available]"
            lines.append(status)
        
        # Add exclusion info if any
        if self.exclude_apps:
            lines.append(f"\nExcluded apps: {', '.join(sorted(self.exclude_apps))}")
        
        return "\n".join(lines)
