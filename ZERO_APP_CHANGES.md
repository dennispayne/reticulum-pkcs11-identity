# Zero-App-Changes Integration Guide

This document explains how reticulum-pkcs11-identity achieves its core promise: **apps make zero changes**.

## The Promise

When you use reticulum-pkcs11-identity, apps like Sideband and Meshchat can use hardware-backed identities **without any code changes whatsoever**.

```python
# In Sideband code (unchanged):
import RNS

# Just create an identity normally
identity = RNS.Identity()

# Behind the scenes, reticulum-pkcs11-identity has:
#   1. Detected that Sideband is calling
#   2. Looked up which PIV slot Sideband uses
#   3. Injected hardware public keys into the identity
#   4. Overridden the sign() method to use the hardware key
#
# Sideband has no idea any of this happened.
```

## How It Works: Three Layers

### Layer 1: Session Persistence (`session_manager.py`)

At **node startup**, the session manager handles PIN once:

```python
# In node startup code (one-time setup):
from reticulum_pkcs11_identity import initialize_session

# PIN entered here (or from env var RNS_PKCS11_PIN)
# Session opened, stored globally
if initialize_session():
    print("Hardware ready!")
else:
    print("Hardware not available, using software identities")
```

Key points:
- PIN entered **once** at node startup
- Session cached globally
- **No re-prompts** during app operations
- Session persists for entire node lifetime
- If YubiKey removed/reinserted: auto-reconnect, no re-prompt

### Layer 2: App-to-Slot Mapping (`app_identity.py`)

When an app creates an identity, the system auto-detects the app and looks up its slot:

```python
# In reticulum_pkcs11_identity internals:

app_name = "sideband"  # Auto-detected from calling code
slot = mapper.get_app_slot(app_name)  # "9a" (already mapped)

if slot:
    # App has a hardware slot ready
    backend = session_manager.get_backend()
    session = backend.open_session(slot)  # Reuses cached session
    ed_public = backend.get_public_key(session, "sign")
    x_public = backend.get_public_key(session, "enc")
    # Ready to inject into identity
```

First time an app runs:
```
Sideband requests identity
  → Check mapping: not found
  → Allocate first available: 9a
  → Generate Ed25519 + X25519 keys
  → Save mapping for next time
  → Return ready identity
```

Subsequent times:
```
Sideband requests identity
  → Check mapping: found (9a)
  → Open session: reuses cached session from startup
  → Get public keys from hardware
  → Return identity (same keys every time)
```

### Layer 3: Transparent RNS Integration (`rns_integration.py`)

**The magic:** When an app creates an `RNS.Identity()`, we intercept it:

```python
# In app code (completely unchanged):
identity = RNS.Identity()

# In reticulum_pkcs11_identity (happens transparently):
#
# 1. Monkey-patch intercepts: _patched_init(identity, create_keys=True)
#
# 2. Detect app name:
#    - Check env var RNS_APP_NAME
#    - Check calling code module name
#    - If Sideband called us: app_name = "sideband"
#
# 3. Get hardware keys:
#    - Lookup: mapper.get_app_slot("sideband") → "9a"
#    - Session exists from startup
#    - Get keys from hardware
#
# 4. Inject keys:
#    - Call original RNS.Identity.__init__()
#    - Override pub_bytes and sig_pub_bytes with hardware keys
#    - Replace sign() method with hardware signing
#
# 5. Return to app:
#    - identity.sign() now uses hardware automatically
#    - identity.pub_bytes are hardware keys
#    - App doesn't know what happened
```

## Startup Sequence

### Option A: Interactive Node Startup

```bash
# 1. User starts node with YubiKey plugged in
python -m reticulum.node

# 2. reticulum-pkcs11-identity detects and initializes
# 3. User prompted: "Enter YubiKey PIN: "
# 4. PIN cached, session opened
# 5. First app (e.g., Sideband) starts
# 6. RNS.Identity() called transparently uses hardware
# 7. No more PIN prompts for rest of session
```

### Option B: Headless Node with ENV Var

```bash
# 1. Set PIN in environment
export RNS_PKCS11_PIN=123456

# 2. Start node
python -m reticulum.node

# 3. reticulum-pkcs11-identity initializes silently (no prompt)
# 4. All apps use hardware transparently
# 5. No user interaction needed
```

### Option C: Batch/Automated

```bash
# 1. Set both PIN and app name
export RNS_PKCS11_PIN=123456
export RNS_APP_NAME=sideband

# 2. Start app
python sideband.py

# 3. App creates identity: RNS.Identity()
# 4. (transparently) Hardware identity injected
# 5. App works as normal, using hardware
```

## Implementation Details

### App Name Detection

Apps are detected in this priority order:

1. **Environment variable** (if set):
   ```bash
   export RNS_APP_NAME=sideband
   ```

2. **Calling module name** (automatic):
   ```python
   # If Sideband's main.py calls RNS.Identity(), 
   # we extract "sideband" from "sideband.main"
   ```

3. **Fallback**: Use software identity (graceful)

### Session Caching

Session manager maintains cache:

```python
_session_manager = None  # Global singleton

def get_session_manager():
    global _session_manager
    if _session_manager is None:
        _session_manager = PKCSIISessionManager()
    return _session_manager

# All code uses same cached instance
```

### Hardware Key Injection

When intercepting `RNS.Identity.__init__()`:

```python
def patched_init(self, create_keys: bool = True):
    # Call original (creates software keys)
    original_init(self, create_keys=create_keys)
    
    # Get hardware keys if available
    hardware_keys = _get_hardware_keys_for_app(app_name)
    if hardware_keys:
        # Replace with hardware keys
        ed_pub, x_pub = hardware_keys
        self.pub_bytes = x_pub
        self.sig_pub_bytes = ed_pub
        
        # Replace sign() method
        self.sign = lambda msg: hardware_sign(msg, slot)
        
        # Mark as hardware-backed
        self._is_hardware_backed = True
```

## Edge Cases Handled

### YubiKey Not Plugged In

```
initialize_session()
  ↓
No provider found
  ↓
Returns False (graceful)
  ↓
Apps use software identities as usual
```

### YubiKey Removed During Operation

```
App calls identity.sign()
  ↓
Hardware signing fails
  ↓
Fallback to software signing (if available)
  ↓
Message still gets sent
```

### No PIN Configured

```
initialize_session(auto_prompt=False)
  ↓
No PIN found
  ↓
Returns False
  ↓
Apps use software identities
```

### PIN Cached, Then Token Removed/Reinserted

```
Node running with open session

User removes YubiKey

App calls sign()
  ↓
Session lost
  ↓
Auto-reconnect with cached PIN (no re-prompt)
  ↓
Signing succeeds
```

## Configuration

### Required (One-time Admin)

Set PIN:
```bash
# Option 1: Environment variable
export RNS_PKCS11_PIN=123456

# Option 2: Config file
echo 'pin = "123456"' > ~/.config/reticulum/pkcs11_identity.conf

# Option 3: Let user be prompted at node startup
# (Just leave PIN unconfigured)
```

### Optional

```bash
# Provider override (auto-detected if not set)
export RNS_PKCS11_PROVIDER=/usr/lib/libykcs11.so

# App name override (auto-detected from code if not set)
export RNS_APP_NAME=sideband

# Token label (for multi-token setups)
# Set in ~/.config/reticulum/pkcs11_identity.conf:
# token_label = "YubiKey PIV #12345"
```

## Testing: Verify It Works

### Test 1: Verify Session Initialization

```python
from reticulum_pkcs11_identity import (
    initialize_session,
    is_session_ready,
    get_session_manager,
)

# Initialize at node startup
if initialize_session():
    print("✓ PKCS#11 session initialized")
    print(f"✓ Backend ready: {get_session_manager().get_backend()}")
else:
    print("✗ No hardware available (software fallback)")
```

### Test 2: Verify Transparent Integration

```python
# Enable transparent injection
from reticulum_pkcs11_identity import enable_hardware_identity_injection

enable_hardware_identity_injection()

# Now when Sideband creates identity, it happens transparently
import RNS
identity = RNS.Identity()

# Check if it used hardware
from reticulum_pkcs11_identity import is_identity_hardware_backed

if is_identity_hardware_backed(identity):
    print("✓ Identity is hardware-backed")
    slot = get_identity_slot(identity)
    print(f"✓ Using PIV slot {slot}")
else:
    print("~ Identity is software (hardware not available)")
```

### Test 3: End-to-End

```bash
# 1. Set PIN
export RNS_PKCS11_PIN=123456

# 2. Run Sideband (or any app)
python sideband.py

# 3. Send a message (sign operation)
#    → Should use hardware signing (no lag, no re-prompt)

# 4. Receive a message (decrypt operation)
#    → Should use hardware ECDH (no lag, no re-prompt)

# 5. Node running for hours?
#    → Still no PIN prompt (session cached)
```

## Summary: Why This Works

1. **One PIN prompt**: At node startup only
2. **Session caching**: Reused for all operations
3. **Transparent detection**: App name auto-detected
4. **Automatic mapping**: First-come-first-served slot allocation
5. **Graceful fallback**: Always works, even without hardware
6. **Zero app changes**: Monkey-patch intercepts identity creation

Result: **Apps literally don't know they're using hardware.**

---

## For Developers

If you're developing a new Reticulum app and want to explicitly ensure hardware is used:

```python
from reticulum_pkcs11_identity import (
    initialize_session,
    enable_hardware_identity_injection,
    is_identity_hardware_backed,
)

# At app startup:
initialize_session(pin=None, auto_prompt=True)  # Prompt for PIN if needed
enable_hardware_identity_injection()  # Enable transparent injection

# Then use RNS normally:
import RNS
identity = RNS.Identity()

# Verify (optional):
if is_identity_hardware_backed(identity):
    print("Using hardware!")
```

That's it. Everything else is transparent.
