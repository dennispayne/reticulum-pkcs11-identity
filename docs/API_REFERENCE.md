# Reticulum PKCS#11 Identity - API Reference

Complete documentation of all public API functions, configuration options, exception types, and integration patterns.

## Session Management API

### `initialize_session()`

Initialize the global PKCS#11 session. **Call this once at node startup.**

**Signature**:
```python
def initialize_session(
    pin: Optional[str] = None,
    provider: Optional[str] = None,
    auto_prompt: bool = True
) -> bool:
```

**Parameters**:
- `pin` (str, optional): YubiKey PIN. If None, tries config/env var, then prompts
- `provider` (str, optional): Path to PKCS#11 provider (.dll/.so). If None, auto-detects
- `auto_prompt` (bool): If True, prompt user for PIN if not available. Default: True

**Returns**: 
- `True` if session initialized successfully
- `False` if hardware unavailable (graceful fallback)

**Raises**:
- No exceptions raised (returns False on any error)

**Usage**:

```python
from reticulum_pkcs11_identity import initialize_session, enable_hardware_identity_injection

# At node startup
if initialize_session(pin="123456"):
    print("Hardware identity session ready")
    enable_hardware_identity_injection()
else:
    print("Hardware not available, using software identities")
```

**Configuration Priority**:
1. Passed `pin` parameter
2. `RNS_PKCS11_PIN` environment variable
3. `~/.config/reticulum/pkcs11_identity.conf` config file
4. User prompt (if `auto_prompt=True`)
5. None (if `auto_prompt=False`)

### `is_session_ready()`

Check if PKCS#11 session is initialized.

**Signature**:
```python
def is_session_ready() -> bool:
```

**Returns**: 
- `True` if session is ready for operations
- `False` if not initialized

**Usage**:

```python
if is_session_ready():
    # Hardware identity operations available
    hw_identity = get_app_identity_keys("sideband")
else:
    # Graceful fallback to software
    pass
```

### `enable_hardware_identity_injection()`

Enable transparent hardware identity injection into RNS.Identity creation.

**Signature**:
```python
def enable_hardware_identity_injection() -> None:
```

**Parameters**: None

**Returns**: None

**Raises**: 
- `ImportError` (silently caught): If RNS module not installed

**Usage**:

```python
from reticulum_pkcs11_identity import initialize_session, enable_hardware_identity_injection

# Setup
if initialize_session():
    enable_hardware_identity_injection()
    
# Now all RNS.Identity creations automatically use hardware keys!
import RNS
identity = RNS.Identity()  # Transparently hardware-backed if app has slot
```

**Important**: Call this **after** `initialize_session()` succeeds.

### `get_session_manager()`

Get the global session manager singleton.

**Signature**:
```python
def get_session_manager() -> PKCSIISessionManager:
```

**Returns**: 
- Global `PKCSIISessionManager` instance

**Usage**:

```python
from reticulum_pkcs11_identity import get_session_manager

manager = get_session_manager()
backend = manager.get_backend()  # Get PKCS11PIVBackend
is_ready = manager.is_ready()   # Check readiness
```

### `shutdown_session()`

Shutdown the global session and cleanup resources.

**Signature**:
```python
def shutdown_session() -> None:
```

**Parameters**: None

**Returns**: None

**Usage**:

```python
# At node shutdown
shutdown_session()
```

---

## App Identity API

### `create_app_hardware_identity()`

Create a hardware-backed identity for an application.

**Signature**:
```python
def create_app_hardware_identity(
    app_name: str,
    slot: Optional[str] = None
) -> Optional[RNS.Identity]:
```

**Parameters**:
- `app_name` (str): Application identifier (e.g., "sideband", "meshchat")
- `slot` (str, optional): Force specific PIV slot ("9a", "9c", "9d", "9e"). If None, auto-allocate

**Returns**:
- `RNS.Identity` if hardware is available and configured
- `None` if hardware unavailable (use software identity as fallback)

**Raises**:
- `SlotNotFoundError` (caught internally): If slot specified but unavailable or invalid
- No exceptions exposed to caller (returns None on error)

**Usage**:

```python
from reticulum_pkcs11_identity import create_app_hardware_identity, initialize_session
import RNS

# Setup
if initialize_session():
    # Create hardware identity for app
    identity = create_app_hardware_identity("sideband")
    
    if identity:
        print(f"Using hardware identity: {identity.hash.hex()}")
        lxmf = RNS.LXMF.LXMFMessenger(identity)
    else:
        # Fallback to software
        identity = RNS.Identity()
```

### `get_app_identity_keys()`

Get public keys for an app's hardware identity.

**Signature**:
```python
def get_app_identity_keys(
    app_name: str
) -> Optional[tuple[bytes, bytes]]:
```

**Parameters**:
- `app_name` (str): Application identifier

**Returns**:
- `(ed25519_public, x25519_public)` if hardware available (each 32 bytes)
- `None` if hardware unavailable

**Usage**:

```python
from reticulum_pkcs11_identity import get_app_identity_keys

keys = get_app_identity_keys("sideband")
if keys:
    ed_pub, x_pub = keys
    print(f"Ed25519 public key: {ed_pub.hex()}")
    print(f"X25519 public key: {x_pub.hex()}")
else:
    print("No hardware keys available")
```

---

## App Slot Mapping API

### `find_app_slot()`

Get PIV slot for an application.

**Signature**:
```python
def find_app_slot(app_name: str) -> Optional[str]:
```

**Parameters**:
- `app_name` (str): Application identifier

**Returns**:
- Slot ID ("9a", "9c", "9d", "9e") if app is mapped
- `None` if app not mapped to any slot

**Usage**:

```python
from reticulum_pkcs11_identity import find_app_slot

slot = find_app_slot("sideband")
if slot:
    print(f"Sideband is using slot {slot}")
else:
    print("Sideband not yet mapped")
```

### `list_available_slots()`

List all currently available (unmapped) PIV slots.

**Signature**:
```python
def list_available_slots() -> list[str]:
```

**Returns**:
- List of available slot IDs (subset of ["9a", "9c", "9d", "9e"])
- Empty list if all slots full

**Usage**:

```python
from reticulum_pkcs11_identity import list_available_slots

available = list_available_slots()
print(f"Available slots: {', '.join(available)}")
# Output: "Available slots: 9a, 9d" (if 9c and 9e in use)
```

### `allocate_slot_for_app()`

Allocate a PIV slot for an application (first-come-first-served).

**Signature**:
```python
def allocate_slot_for_app(
    app_name: str,
    slot: Optional[str] = None
) -> str:
```

**Parameters**:
- `app_name` (str): Application identifier
- `slot` (str, optional): Request specific slot. If None, use first available

**Returns**:
- Allocated slot ID

**Raises**:
- `SlotNotFoundError`: If specific slot requested but unavailable
- `SlotNotFoundError`: If all 4 slots are full (no slots available)

**Usage**:

```python
from reticulum_pkcs11_identity import allocate_slot_for_app

try:
    slot = allocate_slot_for_app("myapp")
    print(f"Allocated slot {slot} to myapp")
except SlotNotFoundError as e:
    print(f"Cannot allocate slot: {e}")
```

### `revoke_app_mapping()`

Revoke an application's mapping (doesn't delete keys, just removes mapping).

**Signature**:
```python
def revoke_app_mapping(app_name: str) -> Optional[str]:
```

**Parameters**:
- `app_name` (str): Application identifier

**Returns**:
- Slot ID that was revoked, or `None` if app not mapped

**Usage**:

```python
from reticulum_pkcs11_identity import revoke_app_mapping

old_slot = revoke_app_mapping("old_app")
if old_slot:
    print(f"Revoked mapping for old_app (was using {old_slot})")
```

**Warning**: After revoking, the keys remain on the YubiKey. Next time the app creates an identity, it will be allocated a different slot.

---

## Discovery API

### `discover_modules()`

Discover available PKCS#11 provider modules on the system.

**Signature**:
```python
def discover_modules() -> list[str]:
```

**Returns**:
- List of PKCS#11 provider paths that exist and are loadable
- May include: libykcs11, opensc-pkcs11, softhsm2

**Usage**:

```python
from reticulum_pkcs11_identity import discover_modules

providers = discover_modules()
for provider in providers:
    print(f"Found provider: {provider}")
# Output example:
# Found provider: C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll
# Found provider: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

### `enumerate_tokens()`

List all PKCS#11 tokens available from a provider.

**Signature**:
```python
def enumerate_tokens(module_path: str) -> list[dict]:
```

**Parameters**:
- `module_path` (str): Path to PKCS#11 provider .dll/.so

**Returns**:
- List of token dictionaries with keys:
  - `label` (str): Token label (e.g., "YubiKey PIV")
  - `model` (str): Token model (e.g., "PKCS#15 emulated")
  - `serial` (str): Token serial number

**Raises**:
- `PKCS11ProviderNotFoundError`: If provider module not found or not a valid PKCS#11 library

**Usage**:

```python
from reticulum_pkcs11_identity import discover_modules, enumerate_tokens

providers = discover_modules()
for provider in providers:
    tokens = enumerate_tokens(provider)
    for token in tokens:
        print(f"Token: {token['label']} (SN: {token['serial']})")
```

---

## Configuration API

### Configuration File Format

**Location**: `~/.config/reticulum/pkcs11_identity.conf`

**Format**: INI-style key-value pairs

```ini
# PKCS#11 Hardware Identity Configuration
# Auto-generated - edit carefully

provider = "auto"
token_label = "YubiKey PIV"
pin = "123456"
pin_env = "RNS_PKCS11_PIN"
```

**Options**:
- `provider` (str): PKCS#11 provider path, or "auto" for auto-detection
- `token_label` (str): Specific token to use (optional)
- `pin` (str): YubiKey PIN (stored in config, only readable by user)
- `pin_env` (str): Environment variable name for PIN (default: "RNS_PKCS11_PIN")

### Environment Variables

**`RNS_PKCS11_PIN`** (recommended for automation)

PIN for YubiKey. Used as fallback if config file not set.

```bash
export RNS_PKCS11_PIN="123456"
python my_app.py
```

**`RNS_APP_NAME`** (optional, for app name detection)

Override app name detection. Useful for scripts or testing.

```bash
export RNS_APP_NAME="my_custom_app"
python identity_script.py
```

### Programmatic Configuration

```python
from reticulum_pkcs11_identity.config import PKCS11Config, ConfigBuilder

# Method 1: Direct config
config = PKCS11Config()
config.set_pin("123456", save=False)  # In-memory only
config.set_provider("auto")

# Method 2: Fluent builder
config = ConfigBuilder() \
    .with_pin("123456", save=False) \
    .with_provider("auto") \
    .with_pin_env_var("MY_CUSTOM_PIN_ENV") \
    .build()

# Method 3: Read existing config
config = PKCS11Config()
pin = config.get_pin()  # Checks: config file → env var → None
provider = config.get_provider()
```

### Configuration Precedence (PIN Resolution)

**Highest to Lowest Priority**:
1. Parameter to `initialize_session(pin="123456")`
2. Environment variable `RNS_PKCS11_PIN`
3. Config file `~/.config/reticulum/pkcs11_identity.conf`
4. User prompt (if `auto_prompt=True`)
5. None (no PIN available)

---

## Exception Hierarchy

### `PKCS11IdentityError` (Base)

Base exception for all PKCS#11 identity operations.

**Usage**:
```python
from reticulum_pkcs11_identity import PKCS11IdentityError

try:
    initialize_session()
except PKCS11IdentityError as e:
    print(f"Hardware identity error: {e}")
```

### `PKCS11BackendError`

Raised when PKCS#11 backend encounters an error (e.g., signing failure, key not found).

**Common Causes**:
- YubiKey disconnected
- Session lost
- Key corrupted on device
- Unsupported key type

**Recovery**:
- Check YubiKey connection
- Retry operation
- Shutdown and reinitialize session

### `PKCS11SessionError`

Raised when PKCS#11 session cannot be established or is lost.

**Common Causes**:
- Token not present
- PKCS#11 provider not loaded
- Session timeout
- PIN locked

**Recovery**:
- Check YubiKey connection and USB power
- Verify PIN not locked (try ykman)
- Reinitialize session

### `PKCS11LoginError`

Raised when PKCS#11 login fails (incorrect PIN, PIN locked).

**Common Causes**:
- Wrong PIN provided
- PIN locked after failed attempts
- YubiKey needs reset

**Recovery**:
- Verify PIN is correct
- Unlock YubiKey with PUK (see ykman docs)
- Check PIN attempts: `ykman piv info`

### `PKCS11KeyNotFoundError`

Raised when requested key is not found on token.

**Common Causes**:
- Key not generated yet
- Slot switched
- Wrong slot number

**Recovery**:
- Check slot mapping: `find_app_slot("app_name")`
- Generate keys if needed
- Verify slot using `enumerate_tokens()`

### `PKCS11ConfigError`

Raised when configuration is missing or invalid.

**Common Causes**:
- Config file corrupted
- PIN not configured
- Provider path invalid
- Invalid slot number

**Recovery**:
- Check config file: `~/.config/reticulum/pkcs11_identity.conf`
- Delete config to reset: `rm ~/.config/reticulum/pkcs11_identity.conf`
- Provide PIN via environment: `RNS_PKCS11_PIN`

### `PKCS11ProviderNotFoundError`

Raised when PKCS#11 provider module cannot be found or loaded.

**Common Causes**:
- Yubico PIV Tool not installed
- OpenSC not installed
- Provider path incorrect
- Wrong provider for operating system

**Recovery**:
- Install Yubico PIV Tool or OpenSC
- Check provider path in config
- Run `discover_modules()` to find available providers

### `SlotNotFoundError`

Raised when requested PIV slot is not available.

**Common Causes**:
- All 4 slots full
- Requested slot doesn't exist
- Slot occupied by another app

**Recovery**:
- List available slots: `list_available_slots()`
- Revoke unused app: `revoke_app_mapping("old_app")`
- Share slot between apps

### `SlotAlreadyOccupiedError`

Raised when trying to allocate a slot already in use.

**Common Causes**:
- Slot already assigned to another app
- Slot shared between apps (expected)
- Configuration conflict

**Recovery**:
- Revoke old app mapping
- Share the slot explicitly
- Use different slot

### `AppNotMappedError`

Raised when querying an app that has no PIV slot mapping.

**Common Causes**:
- App never created identity
- App mapping revoked
- Configuration missing

**Recovery**:
- Create identity first: `create_app_hardware_identity("app")`
- Allocate slot: `allocate_slot_for_app("app")`

---

## Data Structures

### TokenInfo Dictionary

Returned by `enumerate_tokens()`:

```python
{
    "label": str,      # e.g., "YubiKey PIV"
    "model": str,      # e.g., "PKCS#15 emulated"
    "serial": str,     # e.g., "D3704F5ABC123"
}
```

### SlotInfo Dictionary

Internal representation of PIV slot status:

```python
{
    "slot_id": str,        # "9a", "9c", "9d", "9e"
    "name": str,           # "AUTHENTICATION", "SIGNATURE", etc.
    "apps": list[str],     # ["sideband", "meshchat"]
    "available": bool,     # True if no apps
}
```

---

## Integration Patterns

### Pattern 1: Interactive (User-Facing App)

For applications that run with a user at a terminal.

```python
from reticulum_pkcs11_identity import initialize_session, enable_hardware_identity_injection
import RNS

def main():
    # Initialize hardware identity
    if initialize_session(auto_prompt=True):
        print("Hardware identity ready")
        enable_hardware_identity_injection()
    else:
        print("Hardware not available, using software identity")
    
    # Create identity (automatically hardware-backed if available)
    identity = RNS.Identity()
    
    # Rest of application
    lxmf = RNS.LXMF.LXMFMessenger(identity)
    lxmf.send("user", "Hello!")

if __name__ == "__main__":
    main()
```

**Pros**: 
- User can enter PIN interactively
- Graceful fallback if hardware not available

**Cons**:
- Requires user interaction

### Pattern 2: Headless (Server/Automation)

For servers and automated scripts that run without user interaction.

```python
import os
from reticulum_pkcs11_identity import initialize_session, enable_hardware_identity_injection
import RNS

def main():
    # PIN from environment variable (set by admin)
    if not os.environ.get("RNS_PKCS11_PIN"):
        print("ERROR: RNS_PKCS11_PIN not set")
        return
    
    # Initialize with auto_prompt=False (no user interaction)
    if initialize_session(auto_prompt=False):
        enable_hardware_identity_injection()
        print("Hardware identity initialized")
    else:
        # In headless, hardware unavailable = application error
        raise RuntimeError("Hardware identity required but not available")
    
    # Identity automatically hardware-backed
    identity = RNS.Identity()
    # ... start server

if __name__ == "__main__":
    main()
```

**Usage**:
```bash
export RNS_PKCS11_PIN="123456"
export RNS_APP_NAME="my_server"
python server.py
```

**Pros**:
- No user interaction
- Suitable for Docker, systemd, CI/CD

**Cons**:
- PIN in environment (less secure)
- No fallback if hardware unavailable

### Pattern 3: Embedded (Library Integration)

For integrating into existing Reticulum applications without modifying their code.

```python
# Before importing app modules
from reticulum_pkcs11_identity import initialize_session, enable_hardware_identity_injection

# Initialize hardware identity
initialize_session(pin="123456")
enable_hardware_identity_injection()

# Now import app (app creates RNS.Identity normally)
import sideband
sideband.main()  # Identity automatically hardware-backed
```

**Pros**:
- Zero changes to application
- Works with any RNS app

**Cons**:
- PIN must be known before import
- Limited control over error handling

### Pattern 4: Custom (Full Control)

For applications that need fine-grained control over hardware identity lifecycle.

```python
from reticulum_pkcs11_identity import (
    initialize_session,
    create_app_hardware_identity,
    get_app_identity_keys,
    find_app_slot,
    list_available_slots,
)
from reticulum_pkcs11_identity.config import ConfigBuilder
import RNS

def setup_hardware_identity(app_name, pin, provider=None):
    """Custom hardware identity setup with full control."""
    
    # 1. Configure
    config = ConfigBuilder() \
        .with_pin(pin, save=False) \
        .with_provider(provider or "auto") \
        .build()
    
    # 2. Initialize session
    if not initialize_session(auto_prompt=False):
        raise RuntimeError("Hardware identity unavailable")
    
    # 3. Allocate slot if needed
    slot = find_app_slot(app_name)
    if not slot:
        available = list_available_slots()
        if not available:
            raise RuntimeError("All PIV slots are full")
        print(f"Available slots: {', '.join(available)}")
    
    # 4. Create hardware identity
    identity = create_app_hardware_identity(app_name)
    
    # 5. Verify keys
    keys = get_app_identity_keys(app_name)
    if keys:
        ed_pub, x_pub = keys
        print(f"Hardware identity ready:")
        print(f"  Ed25519: {ed_pub.hex()[:16]}...")
        print(f"  X25519:  {x_pub.hex()[:16]}...")
        return identity
    else:
        raise RuntimeError("Failed to get hardware keys")

if __name__ == "__main__":
    identity = setup_hardware_identity("myapp", "123456")
```

**Pros**:
- Maximum control and visibility
- Custom error handling
- Detailed logging

**Cons**:
- More code required
- Responsibility for error handling

---

## Best Practices

### 1. Initialize Early

Call `initialize_session()` **before** creating any identities:

```python
# ✓ Good
if initialize_session():
    enable_hardware_identity_injection()
identity = RNS.Identity()

# ✗ Bad
identity = RNS.Identity()
initialize_session()  # Too late!
```

### 2. Handle Graceful Fallback

Always handle the case where hardware is unavailable:

```python
# ✓ Good
identity = create_app_hardware_identity("app")
if identity is None:
    identity = RNS.Identity()  # Software fallback

# ✗ Bad
identity = create_app_hardware_identity("app")
# Assumes hardware always available
```

### 3. PIN Management

Prefer environment variables for production:

```bash
# ✓ Good (production)
export RNS_PKCS11_PIN="123456"
python app.py

# ✗ Bad (hardcoded)
initialize_session(pin="123456")

# ✓ Good (development)
initialize_session(auto_prompt=True)
```

### 4. App Name Consistency

Use consistent app names across sessions:

```python
# ✓ Good
initialize_session()
enable_hardware_identity_injection()
identity = RNS.Identity()  # Same name → same keys

# ✓ Also good (explicit)
from reticulum_pkcs11_identity import create_app_hardware_identity
identity = create_app_hardware_identity("sideband")

# ✗ Bad (inconsistent)
os.environ["RNS_APP_NAME"] = "sideband"
identity1 = RNS.Identity()
os.environ["RNS_APP_NAME"] = "sideband2"
identity2 = RNS.Identity()  # Different keys!
```

### 5. Error Logging

Log hardware identity setup for debugging:

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if initialize_session():
    logger.info("Hardware identity initialized")
    enable_hardware_identity_injection()
else:
    logger.warning("Hardware identity unavailable, using software")
```

---

## Related Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — Deep-dive into system design
- [IMPLEMENTATION_DETAILS.md](IMPLEMENTATION_DETAILS.md) — PKCS#11 implementation specifics
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — Common issues and solutions
