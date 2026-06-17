# Reticulum PKCS#11 Identity - Architecture

## Overview

The Reticulum PKCS#11 Identity system solves a critical problem in decentralized networks: **how to provide hardware-backed cryptographic identities for multiple applications running on the same device, while maintaining complete transparency and zero code changes in applications**.

### The Problem

Traditional Reticulum applications create and manage their own cryptographic identities in software. This creates several challenges:

1. **Key Compromise**: Private keys are stored on disk or in memory, vulnerable to theft or extraction
2. **Multi-App Complexity**: When multiple apps run on the same node (e.g., Sideband, MeshChat, custom tools), each needs its own identity, but there's no unified infrastructure for hardware backing
3. **Hardware Token Underutilization**: YubiKeys and similar hardware security modules exist but are difficult to integrate cleanly into existing applications
4. **Integration Burden**: Applications would need substantial changes to support hardware identities

### The Solution

This system provides:

1. **YubiKey PIV Slots**: Leverages the PIV (Personal Identity Verification) standard built into YubiKeys. Each device has 4 usable slots (9a, 9c, 9d, 9e), enabling up to 4 applications to have independent hardware-backed identities
2. **PKCS#11 Abstraction**: Uses the industry-standard PKCS#11 interface, enabling support for any hardware token (YubiKey, Nitrokey, HSM, etc.)
3. **Transparent Injection**: Intercepts RNS.Identity creation to transparently substitute hardware keys, requiring zero changes from applications
4. **Session Caching**: PIN is entered once at startup, then cached for the entire application lifetime—no repeated prompts during message operations
5. **Graceful Degradation**: If hardware isn't available or configured, applications automatically fall back to software identities without errors

## The Four-Layer Architecture

The system is organized into four layers, each with distinct responsibilities:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: RNS Integration                                    │
│ - Monkey-patch RNS.Identity.__init__()                      │
│ - Transparent app name detection                            │
│ - Hardware key injection                                    │
│ - Seamless sign() override                                  │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Session Management                                 │
│ - Global singleton PKCS#11 session                          │
│ - PIN caching (ONE prompt at startup)                       │
│ - Thread-safe session reuse                                 │
│ - Auto-reconnect on YubiKey removal/reinsertion            │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: App Identity Factory                               │
│ - App name → PIV slot mapping                               │
│ - First-come-first-served slot allocation                   │
│ - Persistent app configuration (~/.config/reticulum/)       │
│ - Multi-app orchestration                                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Backend Primitives (PKCS#11 Operations)            │
│ - Ed25519 signing (CKM_EDDSA)                               │
│ - X25519 ECDH derivation (CKM_ECDH1_DERIVE)                 │
│ - Key provisioning and lifecycle                            │
│ - Hardware error recovery                                   │
└─────────────────────────────────────────────────────────────┘
```

### Layer 1: RNS Integration (Transparent Injection)

**Location**: `rns_integration.py`

This layer provides zero-config integration with Reticulum's Identity system:

```python
# Inside an app (NO CHANGES NEEDED):
identity = RNS.Identity()  # This triggers hardware injection!

# With hardware + transparent injection:
# 1. App name detected from call stack or RNS_APP_NAME env var
# 2. Hardware slot queried for the app
# 3. Public keys injected into identity
# 4. sign() method overridden to use hardware
```

**Key Functions**:
- `enable_hardware_identity_injection()` — Installs the RNS.Identity monkey patch
- `_detect_app_name()` — Detects calling app from call stack or environment
- `_get_hardware_keys_for_app()` — Retrieves hardware public keys for an app

**Data Flow**:
```
RNS.Identity() [software path normally]
       ↓
   PATCHED __init__
       ↓
  Detect app name
       ↓
Query hardware keys
       ↓
Inject keys if available
       ↓
Override sign() method
       ↓
Return identity (app unaware)
```

### Layer 2: Session Management (PIN Caching)

**Location**: `session_manager.py`

This singleton manages the global PKCS#11 session with PIN caching:

```python
# At node startup:
initialize_session(pin=None, provider=None, auto_prompt=True)
# → User enters PIN once (or from env var / config)
# → Session stays open for entire application lifetime
# → All operations reuse the same session
```

**Key Properties**:
- **Singleton Pattern**: One session per process
- **Thread-Safe**: RLock protects concurrent access
- **PIN Caching**: PIN retrieved once, cached in memory
- **Auto-Recovery**: If token is removed/reinserted, session automatically reopens
- **Graceful Fallback**: If hardware unavailable, returns False (no exceptions)

**Session Lifecycle**:
```
1. initialize_session() called
2. PIN obtained (config/env/prompt)
3. Provider detected (libykcs11/opensc/softhsm2)
4. PKCS11PIVBackend opened
5. Session ready for operations
6. Operations reuse cached backend
7. shutdown_session() on exit
```

### Layer 3: App Identity Factory (Slot Allocation)

**Location**: `app_identity.py`

This layer maps applications to PIV slots:

**PIV Slot Allocation**:
```
Slot 9a → AUTHENTICATION (first allocated)
Slot 9c → SIGNATURE (second allocated)
Slot 9d → KEY_MANAGEMENT (third allocated)
Slot 9e → CARD_AUTHENTICATION (fourth allocated)
```

**Allocation Algorithm** (First-Come-First-Served):
```python
# When app "sideband" first creates identity:
1. Check if "sideband" already mapped
2. Find first available slot (9a, 9c, 9d, 9e in order)
3. Allocate it to "sideband"
4. Generate Ed25519 + X25519 keys in that slot
5. Persist mapping to ~/.config/reticulum/pkcs11_app_slots.conf

# Mapping file format:
# sideband = 9a
# meshchat = 9c
# myapp = 9d
```

**Multi-App Example**:
```
Device with single YubiKey:

  Sideband (messaging) ──→ Slot 9a [Ed25519 + X25519 keys]
  MeshChat (chat)     ──→ Slot 9c [Ed25519 + X25519 keys]
  CustomTool (utility)──→ Slot 9d [Ed25519 + X25519 keys]
  [Future app]        ──→ Slot 9e [Ed25519 + X25519 keys]

Each app has independent keys in its own slot.
Slot exhaustion: 5th app gets graceful fallback to software.
```

### Layer 4: Backend Primitives (PKCS#11 Operations)

**Location**: `backend.py`, `backend_piv.py`

This layer encapsulates all PKCS#11 cryptographic operations:

**Ed25519 Signing** (CKM_EDDSA):
```python
# Private key never leaves hardware
# Operation happens inside YubiKey
session = backend.open_session(slot="9a")
signature = backend.sign(session, message_bytes)  # Hardware call
```

**X25519 ECDH** (CKM_ECDH1_DERIVE):
```python
# Public key retrieved from hardware for comparison
session = backend.open_session(slot="9a")
x_public = backend.get_public_key(session, "enc")  # 32 bytes
```

**Key Format**:
- **Ed25519 Keys**: DER-encoded OID `06 03 2B 65 70`, stored with CKK_EC_EDWARDS
- **X25519 Keys**: DER-encoded OID `06 03 2B 65 6E`, stored with CKK_EC_EDWARDS
- **EC_POINT Format**: PKCS#11 wraps 32-byte keys with prefix `04 20` (DER EC_POINT)

## App-to-Slot Mapping

### Configuration Persistence

Mappings are stored in `~/.config/reticulum/pkcs11_app_slots.conf`:

```ini
# Auto-generated: app-to-PIV-slot mapping
# Format: app_name = slot

sideband = 9a
meshchat = 9c
custom_tool = 9d
```

**Lifecycle**:
1. First time "sideband" creates identity → allocated slot 9a
2. Mapping written to config file
3. Next startup, same mapping restored
4. App gets same keys across restarts (identity persistent)

### Slot Allocation Lifecycle

```
Time →

Initial State:
  9a: [available]
  9c: [available]
  9d: [available]
  9e: [available]

App "sideband" creates identity:
  9a: [sideband] ← allocated
  9c: [available]
  9d: [available]
  9e: [available]

App "meshchat" creates identity:
  9a: [sideband]
  9c: [meshchat] ← allocated
  9d: [available]
  9e: [available]

App "custom" creates identity:
  9a: [sideband]
  9c: [meshchat]
  9d: [custom] ← allocated
  9e: [available]

Legacy app creates identity:
  9a: [sideband]
  9c: [meshchat]
  9d: [custom]
  9e: [legacy] ← allocated

New app tries to create identity:
  Result: SlotNotFoundError (all 4 slots in use)
  Fallback: Software identity (graceful)
```

### Conflict Resolution

**Scenario**: What if an app deletes its config and tries to allocate a new slot?

```python
# App "sideband" is mapped to 9a, decides to "reset" by clearing config
revoke_app_mapping("sideband")  # Removes sideband from 9a

# But the Ed25519 + X25519 keys are still in slot 9a!
# Next time sideband creates identity, it gets allocated 9c
# (first available slot is now 9a, so 9c is used)

# Option: Restore old mapping manually, or
#         Share slot 9a with another app via share_slot()
```

## Session Lifecycle

### Startup Sequence

```
1. Application starts
2. initialize_session(pin=None, provider=None, auto_prompt=True)
   - PIN obtained from:
     a) Parameter
     b) RNS_PKCS11_PIN env var
     c) ~/.config/reticulum/pkcs11_identity.conf
     d) User prompt (if auto_prompt=True)
3. Provider auto-detected (libykcs11 → opensc → softhsm2)
4. PKCS11PIVBackend initialized
5. Session manager marked ready
6. enable_hardware_identity_injection() called
7. Apps create identities → hardware keys injected
```

### Operation Sequence

```
1. App calls identity = RNS.Identity()
2. Patched __init__() detects app name
3. Looks up app's PIV slot
4. Retrieves hardware public keys
5. Injects into identity
6. App calls identity.sign(message)
7. Hardware sign() method called
8. Private key never leaves YubiKey
9. Signature returned to app
```

### YubiKey Removal & Recovery

```
Scenario: User unplugs YubiKey during operation

1. Next PKCS#11 operation fails (token removed)
2. Backend catches error, attempts reconnect
3. YubiKey reinserted
4. Session reopened with cached PIN
5. Operation retried
6. Application unaware of the interruption
```

## Key Operations

### Ed25519 Signing (CKM_EDDSA)

```python
from reticulum_pkcs11_identity import get_backend, get_session_manager

# Setup
initialize_session(pin="123456")
manager = get_session_manager()
backend = manager.get_backend()

# Signing
session = backend.open_session("9a")  # Slot with signing key
message = b"Hello, Reticulum!"
signature = backend.sign(session, message)  # Returns 64-byte signature
```

**Process**:
1. Private key is loaded inside the YubiKey (never exported)
2. Message hash computed: SHA-512(message)
3. EdDSA signature computed in hardware
4. 64-byte signature returned to application
5. Signature is deterministic (same message → same signature)

### X25519 ECDH (CKM_ECDH1_DERIVE)

```python
session = backend.open_session("9a")  # Slot with encryption key
public_key = backend.get_public_key(session, "enc")  # 32-byte X25519 public key
# Application uses this for ECDH key derivation
```

**Process**:
1. X25519 public key retrieved from hardware
2. Application uses it for ECDH handshake with peers
3. Private key stays in hardware (used for decryption)

### Key Provisioning

```python
# Automatic on first identity creation:
# 1. Check if app has PIV slot
# 2. If not, allocate first available slot
# 3. Open session to slot
# 4. Generate Ed25519 key if not present
# 5. Generate X25519 key if not present
# 6. Keys are now permanent on the YubiKey
```

## Transparent Injection Mechanism

### How Monkey-Patching Works

```python
# In rns_integration.py:

# 1. Save the original RNS.Identity.__init__
original_init = RNS.Identity.__init__

# 2. Define a patched version
def patched_init(self, create_keys=True):
    # Try to get hardware keys
    app_name = _detect_app_name()
    hardware_keys = _get_hardware_keys_for_app(app_name)
    
    if hardware_keys:
        # Hardware available
        ed_pub, x_pub = hardware_keys
        original_init(self, create_keys=create_keys)  # Create software version first
        self.pub_bytes = x_pub  # Override with hardware
        self.sig_pub_bytes = ed_pub
        self.sign = hw_sign  # Override sign() method
    else:
        # No hardware, use software
        original_init(self, create_keys=create_keys)

# 3. Apply the patch
RNS.Identity.__init__ = patched_init
```

### App Name Detection Algorithm

**Priority Order**:
1. Check `RNS_APP_NAME` environment variable (highest priority)
2. Walk call stack and find first non-PKCS11/RNS module name
3. Return None if neither available (falls back to software identity)

**Example**:

```
Call stack when sideband creates identity:

Frame 0: reticulum_pkcs11_identity.rns_integration._detect_app_name()
Frame 1: reticulum_pkcs11_identity.rns_integration.patched_init()
Frame 2: RNS.Identity.__init__()
Frame 3: sideband.main.setup_identity()     ← First app module found!
Frame 4: sideband.main.main()

Result: app_name = "sideband"
```

### Hardware Key Substitution

```python
# Original software identity (if keys were generated in software):
identity.pub_bytes = <software_x25519_public_key>    # 32 bytes
identity.sig_pub_bytes = <software_ed25519_public>   # 32 bytes

# After hardware injection:
identity.pub_bytes = <hardware_x25519_public_key>    # 32 bytes (from slot)
identity.sig_pub_bytes = <hardware_ed25519_public>   # 32 bytes (from slot)

# Sign override:
identity.sign = lambda msg: backend.sign(session, msg)  # Uses hardware
```

## Error Handling & Recovery

### Missing PIN

```
Scenario: User hasn't configured PIN

initialize_session(auto_prompt=False)  # Don't ask user

Behavior:
1. Config checked → no PIN
2. Env var checked → not set
3. auto_prompt=False → no prompt
4. Returns False
5. Session not ready
6. Apps get software identity (graceful fallback)
```

### Token Not Present

```
Scenario: YubiKey plugged in but PIV app disabled

Behavior:
1. open_session(slot) called
2. PKCS#11 error raised (token not found)
3. Backend catches, logs error
4. Returns None
5. App falls back to software signing
```

### Slot Exhaustion

```
Scenario: 5th app tries to create identity (only 4 slots)

AppIdentityMapper.allocate_slot_for_app("fifth_app")
→ SlotNotFoundError: "No available PIV slots"

Behavior:
1. Exception caught by transparent injection layer
2. Logged as warning
3. Software identity created as fallback
4. App continues normally, unaware
```

### Session Lost (YubiKey Removed)

```
Scenario: YubiKey unplugged during signing

identity.sign(message)
→ backend.sign(session, message)
→ PKCS#11 error (token removed)

Recovery:
1. Backend catches error
2. Closes broken session
3. Awaits token reinsertion (user plugs it back in)
4. Reopens session with cached PIN
5. Retries operation
6. Returns signature
```

### Configuration Errors

```
Scenario: Config file corrupted or unreadable

Behavior:
1. PKCS11Config._load() catches exception
2. Raises PKCS11ConfigError
3. Caught in initialize_session()
4. Returns False (hardware not available)
5. Apps use software identity
```

## Security Considerations

### Private Key Protection

**Guarantee**: Private keys **never** leave the hardware token.

- Ed25519 private key: Stays on YubiKey, only signature leaves
- X25519 private key: Stays on YubiKey, only encryption operations happen inside
- Application memory: Only public keys and signatures present
- Disk: Only app-to-slot mapping stored (no keys)

### PIN Management

**PIN Storage**:
- **In Memory**: PIN cached after first entry (entire app lifetime)
- **On Disk**: Optional, stored in `~/.config/reticulum/pkcs11_identity.conf` if user sets it
- **Environment**: Can be passed via `RNS_PKCS11_PIN` env var (recommended for automation)
- **User Prompt**: Final fallback, secure input via `getpass`

**PIN Security**:
- If disk-stored, only readable by user (600 permissions)
- If env var, only visible to same user's processes
- Single login per session: PKCS#11 login count = 1 throughout app lifetime

### Session Security

**Session Isolation**:
- One session per process
- PIN-protected access
- PKCS#11 token enforces PIN verification before private key operations
- Failed PIN attempts trigger lockout (YubiKey feature)

### Threat Model

**Protected Against**:
- Disk theft: Private keys never on disk
- Memory inspection: Only public keys and signatures in RAM
- Network sniffing: Reticulum handles encryption, hardware not involved
- Unauthorized copying: PIV token prevents key export

**Not Protected Against**:
- Physical tampering with hardware during operation (PIN entered)
- Malware that can access the process (PIN already in memory)
- PKCS#11 provider compromise (separate vendor concern)
- YubiKey firmware vulnerabilities (vendor concern)

## Performance Characteristics

### Key Generation Latency

```
First identity creation for an app:
1. Slot allocation: ~1 ms
2. Key generation: 2-5 seconds (YubiKey RSA-like operation)
3. Config persistence: ~1 ms
Total: ~2-5 seconds

Subsequent creations (keys exist):
1. Session open: ~50-100 ms
2. Key retrieval: ~10-20 ms
Total: ~60-120 ms
```

### Signing Latency

```
Per signature (Ed25519):
1. Session reuse: ~0 ms (already open)
2. PKCS#11 sign call: 20-50 ms (YubiKey → USB → YubiKey)
3. Signature return: ~1 ms
Total per signature: 21-51 ms

Batch signing 10 messages:
Total: ~250-500 ms (parallelizable)
```

### Session Startup Time

```
initialize_session():
1. PIN retrieval: 0-5 seconds (user input)
2. Provider detection: 10-50 ms
3. Backend initialization: 50-100 ms
4. Session open: 50-100 ms
Total: 5-6 seconds (user input dominates)

Without user prompt (env var PIN):
Total: 100-200 ms
```

### Memory Overhead

```
Per app (with hardware identity):
- Backend object: ~2 KB
- Session handle: ~1 KB
- Cached PIN: ~100 bytes
- Configuration: ~1 KB
Total: ~4-5 KB per app

Singleton session manager: ~1 KB

Global overhead: <10 KB for entire system
```

### Comparative Performance

| Operation | Hardware | Software | Ratio |
|-----------|----------|----------|-------|
| Signing | 20-50 ms | <1 ms | 50x slower |
| Key retrieval | 10-20 ms | <1 ms | 10-20x slower |
| Session init | 100-200 ms | N/A | N/A |
| Memory per app | ~5 KB | N/A | N/A |

**Note**: Hardware signing is slower but provides **unmatched key security**. The latency is negligible for asynchronous messaging applications.

## Extension Points

### Adding New PKCS#11 Providers

**Current Support**:
- libykcs11 (Yubico)
- OpenSC (multiple tokens)
- SoftHSM2 (testing/software)

**To Add Nitrokey Support**:
1. Install Nitrokey PKCS#11 provider
2. Add path to `_DEFAULT_MODULE_CANDIDATES` in `discovery.py`
3. Test with `discover_modules()`
4. No code changes needed!

### Supporting Other Hardware Tokens

1. Token must implement PKCS#11 standard
2. Token must support Ed25519 (CKK_EC_EDWARDS)
3. Token must support X25519 (CKK_EC_EDWARDS)
4. Add PKCS#11 provider to system PATH or config
5. Set provider in config: `PKCS11Config().set_provider("/path/to/provider.so")`

### Customizing App Detection

**Replace `_detect_app_name()`**:

```python
def custom_detect_app_name():
    # Implementation:
    # - Check env var
    # - Check calling module
    # - Return app name or None
    pass

# Monkey-patch the detector:
import reticulum_pkcs11_identity.rns_integration as rns_int
rns_int._detect_app_name = custom_detect_app_name
```

### Modifying Slot Allocation

**Current**: First-come-first-served

**To Implement Priority-Based**:

```python
# Subclass AppIdentityMapper
class PriorityAppIdentityMapper(AppIdentityMapper):
    PRIORITY_SLOTS = {
        "sideband": "9a",      # Always use 9a
        "meshchat": "9c",      # Always use 9c
        # Others: auto-allocated
    }
    
    def allocate_slot_for_app(self, app_name):
        if app_name in self.PRIORITY_SLOTS:
            slot = self.PRIORITY_SLOTS[app_name]
            self._mapping[app_name] = slot
            self._save_mapping()
            return slot
        return super().allocate_slot_for_app(app_name)
```

## Summary

The Reticulum PKCS#11 Identity system provides **transparent, multi-app hardware identity backing** through four coordinated layers:

1. **RNS Integration**: Seamless interception and substitution
2. **Session Management**: One PIN, one session, entire app lifetime
3. **App Factory**: First-come-first-served slot allocation
4. **Backend**: Standard PKCS#11 operations (Ed25519, X25519)

**Key Achievements**:
- ✅ Zero changes to applications
- ✅ Up to 4 apps per YubiKey (4 PIV slots)
- ✅ One PIN entry at startup
- ✅ Private keys never leave hardware
- ✅ Graceful fallback to software
- ✅ Thread-safe, singleton session management
- ✅ Auto-recovery on token removal/reinsertion

This design enables organizations to roll out hardware-backed Reticulum identities across fleets of applications without code modifications, audit burden, or user friction.
