"""
CLI tool for reticulum_pkcs11_identity status reporting.

Provides system state visibility for PKCS#11-backed identities including:
  - Configuration status
  - Running apps and their identity modes
  - Token information and slot usage
  - System warnings and issues
"""

import argparse
import logging
import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set

try:
    import tabulate
except ImportError:
    tabulate = None

from .app_identity import AppIdentityMapper, PIV_SLOTS, PIV_SLOT_NAMES
from .config import load_hardware_identity_config
from .discovery import enumerate_token_inventory, probe_piv_slots


logger = logging.getLogger(__name__)

# Common Reticulum app names (used for app detection)
COMMON_RETICULUM_APPS = {
    "meshchat",
    "sideband",
    "nomad-network",
    "telepath",
    "tnc",
    "tnc-kiss",
}


class StatusReporter:
    """Generates system status report for PKCS#11 identity."""

    def __init__(self):
        """Initialize status reporter."""
        self.config = load_hardware_identity_config()
        self.mapper = None
        self.warnings: List[str] = []
        self.running_apps: Set[str] = set()
        
        if self.config.get("exclude_apps"):
            self.mapper = AppIdentityMapper(exclude_apps=self.config["exclude_apps"])
        else:
            self.mapper = AppIdentityMapper()
        
        # Try to detect running apps
        self._detect_running_apps()

    def _detect_running_apps(self) -> None:
        """Detect running Reticulum apps."""
        try:
            # Try using psutil if available
            try:
                import psutil
                for proc in psutil.process_iter(["name"]):
                    try:
                        proc_name = proc.name().lower()
                        # Check if any known Reticulum app is running
                        for app in COMMON_RETICULUM_APPS:
                            if app in proc_name:
                                self.running_apps.add(app)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except ImportError:
                # Fallback: use subprocess to list processes
                self._detect_running_apps_subprocess()
        except Exception as e:
            logger.debug(f"Failed to detect running apps: {e}")

    def _detect_running_apps_subprocess(self) -> None:
        """Fallback method to detect running apps using subprocess."""
        try:
            if sys.platform == "win32":
                # Windows: use tasklist
                result = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=5)
                output = result.stdout.lower()
            else:
                # Unix: use ps
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
                output = result.stdout.lower()
            
            for app in COMMON_RETICULUM_APPS:
                if app in output:
                    self.running_apps.add(app)
        except Exception as e:
            logger.debug(f"Failed to detect running apps via subprocess: {e}")

    def get_configuration_section(self) -> List[Tuple[str, str]]:
        """
        Get configuration section data.
        
        Returns:
            List of (key, value) tuples for display
        """
        rows = []
        
        # Enabled status
        enabled = self.config.get("enabled", False)
        rows.append(("Enabled", "[+] Yes" if enabled else "[-] No"))
        
        # Provider information
        provider = self.config.get("provider")
        if provider:
            rows.append(("Provider (path)", provider))
        else:
            rows.append(("Provider (path)", "(not configured)"))
            self.warnings.append("Provider not configured")
        
        # Token information
        token_label = self.config.get("token_label")
        if token_label:
            rows.append(("Token (label)", token_label))
        else:
            rows.append(("Token (label)", "(not configured)"))
            if enabled and not provider:
                self.warnings.append("Token label not configured")
        
        # Try to get token info if available
        try:
            token_info = self._query_token_info()
            if token_info:
                if "serial" in token_info:
                    rows.append(("Token (serial)", token_info["serial"]))
                if "slots_available" in token_info:
                    rows.append(("Slots available", str(token_info["slots_available"])))
        except Exception as e:
            logger.debug(f"Could not query token info: {e}")
        
        # Excluded apps
        excluded = self.config.get("exclude_apps", [])
        if excluded:
            rows.append(("Excluded apps", ", ".join(excluded)))
        else:
            rows.append(("Excluded apps", "(none)"))
        
        return rows

    def get_apps_section(self) -> List[List[str]]:
        """
        Get apps table data.
        
        Returns:
            List of rows with [App Name, Status, Identity Mode, Slot]
        """
        rows = []
        all_apps: Set[str] = set()
        
        # Get all known apps from the mapper
        if self.mapper and hasattr(self.mapper, '_mapping'):
            for mapping_info in self.mapper._mapping.values():
                app_name = mapping_info.get("app_name")
                if app_name:
                    all_apps.add(app_name)
        
        # Add excluded apps
        excluded = self.config.get("exclude_apps", [])
        all_apps.update(excluded)
        
        # Add running apps
        all_apps.update(self.running_apps)
        
        # Generate rows for each app
        for app_name in sorted(all_apps):
            status = self._get_app_status(app_name)
            identity_mode = self._get_identity_mode(app_name)
            slot = self._get_app_slot(app_name)
            
            rows.append([app_name, status, identity_mode, slot])
        
        return rows

    def get_tokens_section(self) -> List[List[str]]:
        """
        Get tokens/slots table data.
        
        Returns:
            List of rows with [Slot, App(s)]
        """
        rows = []
        
        if not self.mapper:
            return rows
        
        # Build slot usage information
        for slot in PIV_SLOTS:
            slot_name = PIV_SLOT_NAMES.get(slot, "UNKNOWN")
            apps = self.mapper.get_slot_apps(slot)
            
            if apps:
                slot_display = f"PIV:{slot.upper()} ({slot_name})"
                app_list = ", ".join(sorted(apps))
                rows.append([slot_display, app_list])
        
        return rows

    def get_warnings_section(self) -> List[str]:
        """
        Get system warnings.
        
        Returns:
            List of warning messages
        """
        warnings = list(self.warnings)
        
        # Check for multiple hardware providers
        if self.config.get("detected_providers"):
            providers = self.config["detected_providers"]
            hw_providers = [p for p, info in providers.items() if info.get("type") == "hardware"]
            if len(hw_providers) > 1:
                warnings.append(f"Multiple hardware providers detected: {', '.join(hw_providers)}")
        
        # Check for slot conflicts
        if self.mapper:
            for slot in PIV_SLOTS:
                apps = self.mapper.get_slot_apps(slot)
                if len(apps) > 1:
                    warnings.append(f"Slot PIV:{slot.upper()} is shared by multiple apps: {', '.join(apps)}")
        
        return warnings

    def _query_token_info(self) -> Optional[Dict[str, Any]]:
        """
        Query token info from PKCS#11 provider if available.
        
        Returns:
            Dict with token information or None
        """
        try:
            provider = self.config.get("provider")
            token_label = self.config.get("token_label")
            
            if not provider or not token_label:
                return None
            
            # Try to enumerate tokens
            inventory = enumerate_token_inventory([provider])
            
            # Find matching token by label
            for token_info in inventory.get("tokens", []):
                if token_info.get("label") == token_label:
                    return {
                        "label": token_info.get("label"),
                        "serial": token_info.get("serial"),
                        "slots_available": len(PIV_SLOTS),
                    }
        except Exception as e:
            logger.debug(f"Failed to query token info: {e}")
        
        return None

    def _get_app_status(self, app_name: str) -> str:
        """Get running/stopped status of app."""
        if app_name in self.running_apps:
            return "running"
        return "stopped"

    def _get_identity_mode(self, app_name: str) -> str:
        """Get identity mode for app."""
        if not self.mapper:
            return "not-configured"
        
        if self.mapper.is_app_excluded(app_name):
            return "excluded"
        
        slot = self.mapper.get_app_slot(app_name)
        if slot:
            return "hw-backed"
        
        return "not-configured"

    def _get_app_slot(self, app_name: str) -> str:
        """Get slot assignment for app."""
        if not self.mapper:
            return "(no identity)"
        
        if self.mapper.is_app_excluded(app_name):
            return "(software)"
        
        slot = self.mapper.get_app_slot(app_name)
        if slot:
            return f"PIV:{slot.upper()}"
        
        return "(no identity)"

    def print_status(self):
        """Print status report to stdout."""
        print("\n" + "=" * 70)
        print("RETICULUM PKCS#11 IDENTITY STATUS".center(70))
        print("=" * 70 + "\n")
        
        # Configuration section
        print("CONFIGURATION:")
        print("-" * 70)
        config_rows = self.get_configuration_section()
        for key, value in config_rows:
            print(f"  {key:<25} {value}")
        print()
        
        # Apps section
        apps_rows = self.get_apps_section()
        if apps_rows:
            print("APPS:")
            print("-" * 70)
            if tabulate:
                headers = ["App Name", "Status", "Identity Mode", "Slot"]
                print(tabulate.tabulate(apps_rows, headers=headers, tablefmt="grid"))
            else:
                # Simple text table fallback
                print(f"  {'App Name':<20} {'Status':<10} {'Identity Mode':<15} {'Slot':<20}")
                print("  " + "-" * 65)
                for row in apps_rows:
                    print(f"  {row[0]:<20} {row[1]:<10} {row[2]:<15} {row[3]:<20}")
            print()
        
        # Tokens section
        tokens_rows = self.get_tokens_section()
        if tokens_rows:
            print("TOKENS (Slot Usage):")
            print("-" * 70)
            if tabulate:
                headers = ["Slot", "App(s)"]
                print(tabulate.tabulate(tokens_rows, headers=headers, tablefmt="grid"))
            else:
                # Simple text table fallback
                print(f"  {'Slot':<35} {'App(s)':<35}")
                print("  " + "-" * 70)
                for row in tokens_rows:
                    print(f"  {row[0]:<35} {row[1]:<35}")
            print()
        
        # Warnings section
        warnings = self.get_warnings_section()
        if warnings:
            print("WARNINGS:")
            print("-" * 70)
            for warning in warnings:
                print(f"  [!] {warning}")
            print()
        else:
            print("(No warnings)")
            print()
        
        print("=" * 70 + "\n")


def status_command(args):
    """Execute status command."""
    reporter = StatusReporter()
    reporter.print_status()


def list_tokens_command(args):
    """List available PKCS#11 tokens and their labels."""
    try:
        from .discovery import discover_pkcs11_modules
        
        print("=" * 70)
        print("AVAILABLE PKCS#11 TOKENS")
        print("=" * 70)
        print()
        
        # Discover providers
        providers = discover_pkcs11_modules()
        if not providers:
            print("[X] No PKCS#11 providers found.")
            print()
            print("Install one of the following:")
            print("  Windows: https://developers.yubico.com/YubiKey/Yubico_PIV_Tool.html")
            print("  macOS: brew install yubico-piv-tool")
            print("  Linux: sudo apt install libykcs11 pcscd")
            print()
            return
        
        print(f"[+] Found {len(providers)} PKCS#11 provider(s)")
        print()
        
        # Try each provider
        found_any = False
        for provider_path in providers:
            try:
                import pkcs11
                
                # Load library with PATH adjustments for Windows DLLs
                lib = None
                try:
                    lib = pkcs11.lib(provider_path)
                except Exception:
                    # Try adding the provider's directory to PATH for Windows DLL dependencies
                    if os.name == 'nt':
                        provider_dir = os.path.dirname(provider_path)
                        old_path = os.environ.get('PATH', '')
                        os.environ['PATH'] = f"{provider_dir};{old_path}"
                        try:
                            lib = pkcs11.lib(provider_path)
                        finally:
                            os.environ['PATH'] = old_path
                
                if not lib:
                    raise Exception("Could not load provider")
                
                slots = lib.get_slots()
                
                print(f"Provider: {provider_path}")
                
                if not slots:
                    print("  (no slots detected)")
                    print()
                    continue
                
                print(f"  Slots: {len(slots)}")
                
                # First try to get token labels
                found_token = False
                for slot in slots:
                    try:
                        token = slot.get_token()
                        label = (token.label if hasattr(token, 'label') else str(token)).strip()
                        serial = token.serial_number if hasattr(token, 'serial_number') else "unknown"
                        
                        if label:
                            print(f"    [Slot {slot.slot_id}] Token: {label}")
                            print(f"      Serial: {serial}")
                            print(f"      Use in config: token_label = {label}")
                            found_token = True
                            found_any = True
                        else:
                            print(f"    [Slot {slot.slot_id}] (token present but no label)")
                    except Exception as e:
                        # TokenNotPresent is expected if keys exist but no identity created yet
                        error_type = type(e).__name__
                        if error_type == 'TokenNotPresent':
                            print(f"    [Slot {slot.slot_id}] (YubiKey detected - ready for first identity)")
                            print(f"      Note: This YubiKey hasn't been initialized with an identity yet")
                            print(f"      Run a Reticulum app to create your first identity")
                            found_any = True
                        else:
                            logger.debug(f"Error reading token: {e}")
                            print(f"    [Slot {slot.slot_id}] (error: {error_type})")
                
                print()
            except Exception as e:
                logger.debug(f"Error querying provider {provider_path}: {e}")
                print(f"  Error: {e}")
                print()
                continue
        
        if found_any:
            print("=" * 70)
            print("Example config with your token:")
            print("=" * 70)
            print()
            print("[hardware_identity]")
            print("enabled = true")
            print("provider = libykcs11")
            print("token_label = <use label from above>")
            print()
        else:
            print("=" * 70)
            print("[X] No tokens detected.")
            print("=" * 70)
            print()
            print("Troubleshooting:")
            print("  1. Is your YubiKey plugged in? Try unplugging and replugging")
            print("  2. On macOS: Try 'ykman info' to verify YubiKey is recognized")
            print("  3. On Linux: Try 'pkcs11-tool --list-slots'")
            print("  4. Check your provider is installed (libykcs11, opensc-pkcs11, etc)")
            print()
        
        print()
        
    except Exception as e:
        logger.debug(f"Error in list_tokens: {e}")
        print(f"[X] Error listing tokens: {e}", file=sys.stderr)
        sys.exit(1)



def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="reticulum-pkcs11-identity",
        description="PKCS#11-backed identity management for Reticulum"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show system status")
    status_parser.set_defaults(func=status_command)
    
    # List tokens command
    list_tokens_parser = subparsers.add_parser("list-tokens", help="List available PKCS#11 tokens and their labels")
    list_tokens_parser.set_defaults(func=list_tokens_command)
    
    # Parse arguments
    args = parser.parse_args()
    
    # If no command specified, show status by default
    if not hasattr(args, "func"):
        status_command(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
