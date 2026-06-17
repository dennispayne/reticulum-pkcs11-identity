"""Example: Generic app setup pattern (applicable to any Reticulum app)."""

from reticulum_pkcs11_identity import (
    get_or_create_hardware_identity,
    get_app_hardware_slot,
    list_all_app_slots,
)


def setup_app_identity(app_name: str):
    """
    Generic pattern for any Reticulum app to use hardware identities.
    
    This is the recommended pattern for Sideband, Meshchat, RNPhone, etc.
    
    Key principle: Zero changes to the app's existing identity creation logic.
    Apps just add this one check at startup.
    
    Args:
        app_name: Unique app identifier (e.g., "sideband", "meshchat")
    """
    
    # Step 1: Try to get hardware identity
    hw_identity = get_or_create_hardware_identity(app_name)
    
    # Step 2: Use it or fall back
    if hw_identity:
        print(f"✓ {app_name}: Hardware identity ready (slot {hw_identity.slot})")
        return create_hardware_backed_identity(app_name, hw_identity)
    else:
        print(f"✗ {app_name}: Hardware not available, using software identity")
        return create_software_identity(app_name)


def create_hardware_backed_identity(app_name: str, hw_identity):
    """Create RNS.Identity with hardware backing."""
    # Your app's logic here
    # Use hw_identity.get_public_keys() and hw_identity.sign()
    pass


def create_software_identity(app_name: str):
    """Create regular software RNS.Identity."""
    # Your app's existing identity creation logic here
    pass


def query_hardware_setup():
    """Query what's currently set up."""
    
    print("Hardware Identity Setup Status")
    print("=" * 50)
    
    slots = list_all_app_slots()
    if slots:
        for app, slot in sorted(slots.items()):
            print(f"  {app:20} -> {slot}")
    else:
        print("  No apps configured for hardware yet")


if __name__ == "__main__":
    # Example 1: First app requesting hardware
    print("\nScenario 1: Sideband starts first")
    setup_app_identity("sideband")
    
    # Example 2: Second app requesting hardware
    print("\nScenario 2: Meshchat starts (gets next slot)")
    setup_app_identity("meshchat")
    
    # Example 3: Query current setup
    print("\nScenario 3: Admin checks what's configured")
    query_hardware_setup()
