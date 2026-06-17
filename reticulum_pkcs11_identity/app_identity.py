"""
App-to-PIV-slot mapper for multi-app identities.

Implements first-come-first-served slot allocation with persistence.
Each app gets its own (or shared) PIV slot, ensuring multiple apps
can have independent hardware-backed identities on the same YubiKey.
"""

import os
from pathlib import Path
from typing import Optional

from .exceptions import (
    AppNotMappedError,
    SlotAlreadyOccupiedError,
    SlotNotFoundError,
    PKCS11ConfigError,
)


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
    Maps app names to PIV slots with first-come-first-served allocation.

    Stores mapping persistently in ~/.config/reticulum/pkcs11_app_slots.conf.
    """

    def __init__(self, config_dir: str | None = None):
        """
        Initialize mapper.

        Args:
            config_dir: Config directory. Defaults to ~/.config/reticulum/
        """
        if config_dir is None:
            config_dir = os.path.expanduser("~/.config/reticulum")
        
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "pkcs11_app_slots.conf"
        self._mapping = {}  # app_name -> slot
        self._slot_apps = {}  # slot -> app_names (list, for sharing)
        
        # Load existing mapping
        self._load_mapping()

    def _load_mapping(self) -> None:
        """Load app->slot mapping from config file."""
        self._mapping.clear()
        self._slot_apps.clear()
        
        if not self.config_file.exists():
            return
        
        try:
            with open(self.config_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    if "=" not in line:
                        continue
                    
                    app, slots_str = line.split("=", 1)
                    app = app.strip()
                    
                    # Parse slot(s) - can be comma-separated for shared slots
                    slots = [s.strip() for s in slots_str.strip().split(",")]
                    
                    # Store mapping (use first slot as primary)
                    if slots:
                        self._mapping[app] = slots[0]
                        
                        # Track which apps use each slot
                        for slot in slots:
                            if slot not in self._slot_apps:
                                self._slot_apps[slot] = []
                            if app not in self._slot_apps[slot]:
                                self._slot_apps[slot].append(app)
        except Exception as e:
            raise PKCS11ConfigError(f"Failed to load app mapping: {e}") from e

    def _save_mapping(self) -> None:
        """Save app->slot mapping to config file."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, "w") as f:
                f.write("# Auto-generated: app-to-PIV-slot mapping\n")
                f.write("# Format: app_name = slot\n")
                f.write("# Apps can share slots (comma-separated)\n\n")
                
                # Write in sorted order for consistency
                for app in sorted(self._mapping.keys()):
                    slot = self._mapping[app]
                    # Check if slot is shared
                    apps_on_slot = self._slot_apps.get(slot, [])
                    if len(apps_on_slot) > 1:
                        # Show as shared
                        slots_str = ",".join(sorted(apps_on_slot))
                        if app == apps_on_slot[0]:  # Only write once per slot
                            f.write(f"{slot} = {slots_str}\n")
                    else:
                        f.write(f"{app} = {slot}\n")
        except Exception as e:
            raise PKCS11ConfigError(f"Failed to save app mapping: {e}") from e

    def get_app_slot(self, app_name: str) -> Optional[str]:
        """
        Get PIV slot for an app.

        Args:
            app_name: Application name

        Returns:
            Slot ID ("9a", "9c", "9d", "9e") or None if not mapped
        """
        return self._mapping.get(app_name)

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

    def allocate_slot_for_app(self, app_name: str) -> str:
        """
        Allocate first available slot for app (first-come-first-served).

        Args:
            app_name: Application name

        Returns:
            Allocated slot ID

        Raises:
            SlotNotFoundError: If all slots are full
        """
        # Check if app already has a slot
        if app_name in self._mapping:
            return self._mapping[app_name]
        
        # Find first available slot
        for slot in PIV_SLOTS:
            if self.is_slot_available(slot):
                self._mapping[app_name] = slot
                if slot not in self._slot_apps:
                    self._slot_apps[slot] = []
                self._slot_apps[slot].append(app_name)
                self._save_mapping()
                return slot
        
        raise SlotNotFoundError(
            f"No available PIV slots. All {len(PIV_SLOTS)} slots are in use."
        )

    def share_slot(self, slot: str, app_name: str) -> None:
        """
        Make an app share a slot with existing app(s).

        Args:
            slot: Slot ID
            app_name: Application name to add to slot

        Raises:
            SlotNotFoundError: If slot doesn't exist
            SlotAlreadyOccupiedError: If app already has a different slot
        """
        if slot not in PIV_SLOTS:
            raise SlotNotFoundError(f"Invalid slot: {slot}")
        
        # Check if app already mapped
        if app_name in self._mapping:
            current_slot = self._mapping[app_name]
            if current_slot == slot:
                return  # Already on this slot
            raise SlotAlreadyOccupiedError(
                f"App {app_name} already uses slot {current_slot}"
            )
        
        # Add app to slot
        if slot not in self._slot_apps:
            self._slot_apps[slot] = []
        
        self._mapping[app_name] = slot
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
        if app_name not in self._mapping:
            return None
        
        slot = self._mapping.pop(app_name)
        
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
        return "\n".join(lines)
