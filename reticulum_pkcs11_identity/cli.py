"""
CLI tool for reticulum_pkcs11_identity status reporting.

Provides system state visibility for the PKCS#11-backed hardware identity:
  - Configuration status
  - Token information
  - System warnings and issues

This tool targets the production model: a single hardware identity shared
across apps via RNS aspects. The opt-in multi-identity / per-app-slot machinery
lives under ``reticulum_pkcs11_identity.experimental`` and is intentionally not
surfaced here.
"""

import argparse
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple, Any

try:
    import tabulate
except ImportError:
    tabulate = None

from .config import load_hardware_identity_config
from .discovery import enumerate_token_inventory


logger = logging.getLogger(__name__)


class StatusReporter:
    """Generates a system status report for the hardware identity."""

    def __init__(self):
        """Initialize status reporter."""
        self.config = load_hardware_identity_config()
        self.warnings: List[str] = []

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
            if token_info and "serial" in token_info:
                rows.append(("Token (serial)", token_info["serial"]))
        except Exception as e:
            logger.debug(f"Could not query token info: {e}")

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
            if isinstance(providers, dict):
                hw_providers = [
                    p for p, info in providers.items()
                    if isinstance(info, dict) and info.get("type") == "hardware"
                ]
                if len(hw_providers) > 1:
                    warnings.append(
                        f"Multiple hardware providers detected: {', '.join(hw_providers)}"
                    )

        return warnings

    def _query_token_info(self) -> Optional[Dict[str, Any]]:
        """
        Query token info from the PKCS#11 provider if available.

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

            # Find matching token by label. enumerate_token_inventory returns a
            # list of per-token dicts (keys: token_label, serial, slot_id, ...).
            for token_info in inventory:
                if token_info.get("token_label") == token_label:
                    return {
                        "label": token_info.get("token_label"),
                        "serial": token_info.get("serial"),
                    }
        except Exception as e:
            logger.debug(f"Failed to query token info: {e}")

        return None

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
            print("Install a PKCS#11 provider for your hardware token, then try")
            print("again. (Development testing was done with a YubiKey via the")
            print("Yubico PIV Tool / libykcs11 provider.)")
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
                for slot in slots:
                    try:
                        token = slot.get_token()
                        label = (token.label if hasattr(token, 'label') else str(token)).strip()
                        serial = getattr(token, 'serial', None) or "unknown"

                        if label:
                            print(f"    [Slot {slot.slot_id}] Token: {label}")
                            print(f"      Serial: {serial}")
                            print(f"      Use in config: token_label = {label}")
                            found_any = True
                        else:
                            print(f"    [Slot {slot.slot_id}] (token present but no label)")
                    except Exception as e:
                        # TokenNotPresent is expected if keys exist but no identity created yet
                        error_type = type(e).__name__
                        if error_type == 'TokenNotPresent':
                            print(f"    [Slot {slot.slot_id}] (hardware token detected - ready for first identity)")
                            print(f"      Note: This token hasn't been initialized with an identity yet")
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
            print("  1. Is your hardware token plugged in? Try unplugging and replugging")
            print("  2. Verify your OS / PKCS#11 provider recognizes the token")
            print("  3. Check your provider is installed (e.g. libykcs11, opensc-pkcs11)")
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
