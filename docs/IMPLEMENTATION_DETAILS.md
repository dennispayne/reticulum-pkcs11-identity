# Reticulum PKCS#11 Identity - Implementation Details

Low-level technical details for developers who need to understand or extend the cryptographic operations, PKCS#11 mechanisms, and internal data structures.

## Backend PKCS#11 Operations

### PKCS#11 Session Lifecycle

**Opening a Session**:

```python
import pkcs11

# 1. Load PKCS#11 library
lib = pkcs11.PyKCS11Lib()
lib.load("/path/to/libykcs11.dll")  # or .so on Linux

# 2. Enumerate slots
slots = lib.getSlotList()

# 3. Open session on specific slot
# Slot 0xD for PIV slot 9a, 0xE for 9c, 0xF for 9d, 0x10 for 9e
session = lib.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)

# 4. Login (authenticate user with PIN)
session.login("123456")  # PIN is user "password"

# 5. Session ready for operations
```

**Session State Machine**:
```
Initial
  ↓
load()
  ↓
openSession()
  ↓
login()
  ↓
READY (can sign, derive, find keys)
  ↓
logout() / closeSession()
  ↓
Initial
```

### Ed25519 Signing (CKM_EDDSA)

**PKCS#11 Mechanism**:
```python
from pkcs11 import Mechanism

mechanism = Mechanism(CKM_EDDSA)  # Ed25519 signature scheme
```

**Key Format (Private)**:
- **Key Type**: `CKK_EC_EDWARDS`
- **OID**: `1.3.101.112` (Ed25519 curve)
- **DER Encoding**: `06 03 2B 65 70`
- **Attributes**:
  - `CKA_CLASS`: `CKO_PRIVATE_KEY`
  - `CKA_TOKEN`: `True` (persistent on hardware)
  - `CKA_EXTRACTABLE`: `False` (never exported)
  - `CKA_SIGN`: `True` (can sign)

**Key Format (Public)**:
- **Type**: `CKK_EC_EDWARDS`
- **EC_POINT Format**: 34 bytes
  - Prefix: `04 20` (DER encoding: UNCOMPRESSED point, 32 bytes follow)
  - Data: 32-byte Ed25519 public key
  - Total: 2 + 32 = 34 bytes

**Signing Operation**:

```python
# 1. Find signing private key
objects = session.findObjects(
    template=[
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_KEY_TYPE, CKK_EC_EDWARDS),
        (CKA_LABEL, "sign"),  # PIV label
    ]
)

private_key = objects[0]

# 2. Sign message
message = b"Hello, Reticulum!"
signature_bytes = session.sign(
    private_key,
    message,
    Mechanism(CKM_EDDSA)
)

# 3. Result: 64-byte Ed25519 signature
assert len(signature_bytes) == 64
```

**Signature Determinism**:
Ed25519 produces deterministic signatures (RFC 8032):
- Same message → Same signature
- Verifiable by peers using public key
- No randomness involved

### X25519 ECDH (CKM_ECDH1_DERIVE)

**PKCS#11 Mechanism**:
```python
from pkcs11 import Mechanism, KDF

mechanism = Mechanism(
    CKM_ECDH1_DERIVE,
    {
        "kdf": KDF.SHA256,
        "sharedData": peer_public_key,  # 32 bytes
    }
)
```

**Key Format (Private)**:
- **Key Type**: `CKK_EC_EDWARDS` (Montgomery curve variant)
- **OID**: `1.3.101.110` (X25519 curve)
- **DER Encoding**: `06 03 2B 65 6E`
- **Attributes**:
  - `CKA_CLASS`: `CKO_PRIVATE_KEY`
  - `CKA_DERIVE`: `True` (can derive keys)
  - `CKA_EXTRACTABLE`: `False`

**Key Format (Public)**:
- **Type**: `CKK_EC_EDWARDS`
- **EC_POINT Format**: 34 bytes (same as Ed25519)
  - Prefix: `04 20`
  - Data: 32-byte X25519 public key
  - Total: 2 + 32 = 34 bytes

**ECDH Operation**:

```python
# 1. Find encryption private key
objects = session.findObjects(
    template=[
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_KEY_TYPE, CKK_EC_EDWARDS),
        (CKA_LABEL, "enc"),  # PIV label
    ]
)

private_key = objects[0]

# 2. Derive shared secret with peer public key
peer_public = b"\x04\x20" + peer_x25519_public  # 34 bytes EC_POINT
derived_key = session.deriveKey(
    private_key,
    Mechanism(
        CKM_ECDH1_DERIVE,
        {
            "kdf": KDF.SHA256,
            "sharedData": peer_public,
        }
    ),
    CKK_AES,  # Derive 256-bit AES key
    {
        CKA_VALUE_LEN: 32,  # 256 bits
    }
)

# 3. Result: 32-byte shared secret
shared_secret = session.getAttributeValue(derived_key, [CKA_VALUE])[0]
assert len(shared_secret) == 32
```

**KDF (Key Derivation Function)**:
- Uses SHA256 as specified in Reticulum spec
- Derives 256-bit symmetric keys for message encryption
- Peer provides public key, hardware provides private key, hardware computes shared secret

### EC_POINT Encoding

**PKCS#11 Standard**:
All elliptic curve keys are encoded as EC_POINT in PKCS#11:

```
EC_POINT ::= BER-encoded
  04 <length> <x-coordinate> <y-coordinate>
```

For 32-byte keys (Edwards curves):
- Prefix: `04 20` (UNCOMPRESSED, 32 bytes of key data follow)
- Key Data: 32 bytes
- Total: 34 bytes

**Conversion Functions** (in backend.py):

```python
def _ec_point_to_raw(ec_point: bytes) -> bytes:
    """Strip DER prefix to get raw key."""
    if len(ec_point) == 34 and ec_point[:2] == b'\x04\x20':
        return ec_point[2:]  # Return 32-byte raw key
    raise PKCS11BackendError(f"Unexpected EC_POINT format")

def raw_to_ec_point(raw: bytes) -> bytes:
    """Add DER prefix to raw key."""
    if len(raw) != 32:
        raise PKCS11BackendError(f"Expected 32-byte raw key")
    return b'\x04\x20' + raw  # Return 34-byte EC_POINT
```

**Why This Matters**:
- PKCS#11 always uses EC_POINT format (34 bytes)
- Reticulum keys are raw 32-byte keys
- Conversion happens transparently in backend

## PIV Slot Mapping

### PIV Slots on YubiKey

**Standard Slots**:

| Slot | Name | Purpose | Usage |
|------|------|---------|-------|
| 9a | AUTHENTICATION | Authentication key | Used for identity signing |
| 9c | SIGNATURE | Signature key | Can be used for alternative signing |
| 9d | KEY_MANAGEMENT | Key encipherment | Used for ECDH key exchange |
| 9e | CARD_AUTHENTICATION | Card authentication | Can be used for authentication |

**Example: Sideband on 9a**:
```
PIV Slot 9a (AUTHENTICATION):
  ├─ Ed25519 private key (never leaves YubiKey)
  ├─ Ed25519 public key (available for signing)
  ├─ X25519 private key (never leaves YubiKey)
  └─ X25519 public key (available for ECDH)

Both keys generated and stored together in one slot.
```

**Why Not 9b or 9f**:
- Slot 9b: Asymmetric (not supported on all YubiKeys)
- Slot 9f: Certification Authority credential (reserved)
- Slots 9a, 9c, 9d, 9e: Maximum 4 keys per YubiKey (sufficient for 4 apps)

### Key Storage Format on YubiKey

**Physical Storage**:
```
YubiKey
├─ Slot 9a (AUTHENTICATION)
│  ├─ CRT (Certificate, optional)
│  ├─ Ed25519 Priv (private key, encrypted, read-protected)
│  └─ Ed25519 Pub (public key)
├─ Slot 9c (SIGNATURE)
│  ├─ CRT
│  └─ Keys...
├─ Slot 9d (KEY_MANAGEMENT)
│  ├─ CRT
│  └─ Keys...
└─ Slot 9e (CARD_AUTHENTICATION)
   ├─ CRT
   └─ Keys...
```

**Access Control**:
- Private keys: Require PIN (always enforced by hardware)
- Public keys: Accessible without PIN
- Read operations: Allowed after PIN authentication
- Export: Forbidden (PKCS#11 enforces `CKA_EXTRACTABLE = False`)

## App Name Detection Algorithm

### Stack Walking

**Principle**: Walk the Python call stack and find the first non-PKCS11/RNS module.

**Implementation** (from `rns_integration.py`):

```python
def _detect_app_name() -> Optional[str]:
    # Priority 1: Environment variable
    app_name = os.environ.get("RNS_APP_NAME")
    if app_name:
        return app_name
    
    # Priority 2: Call stack inspection
    frame = inspect.currentframe()
    while frame:
        module_name = frame.f_globals.get("__name__", "")
        
        # Skip this module and RNS internals
        if "reticulum_pkcs11_identity" in module_name or "RNS" in module_name:
            frame = frame.f_back
            continue
        
        # Found app module
        if module_name and "." in module_name:
            # e.g., "sideband.main" → "sideband"
            return module_name.split(".")[0]
        elif module_name:
            return module_name
        
        frame = frame.f_back
    
    return None
```

**Call Stack Example**:

```
Frame 0: reticulum_pkcs11_identity.rns_integration._detect_app_name
Frame 1: reticulum_pkcs11_identity.rns_integration.patched_init
Frame 2: RNS.Identity.__init__
Frame 3: sideband.messaging.setup_identity
Frame 4: sideband.ui.main
Frame 5: __main__

Walking up:
  - Frame 0: Skip (reticulum_pkcs11_identity)
  - Frame 1: Skip (reticulum_pkcs11_identity)
  - Frame 2: Skip (RNS)
  - Frame 3: Found! module_name = "sideband.messaging"
  - Extract: "sideband" (first part before dot)
  - Return: "sideband"
```

**Edge Cases**:

```python
# Case 1: Single-module app
# Frame 3: module_name = "myapp"
# Return: "myapp" (no dot, return as-is)

# Case 2: Nested app structure
# Frame 3: module_name = "com.example.app.main"
# Return: "com" (first part before first dot)
# Note: Could be improved to return "com.example.app"

# Case 3: No app module found
# All frames are RNS/PKCS11
# Return: None (no app name detected, use software identity)

# Case 4: RNS_APP_NAME set
# Check environment first, return immediately
# Stack walking skipped
```

## Session Manager Implementation

### Singleton Pattern

**Objective**: One PKCS#11 session per Python process.

**Implementation**:

```python
class PKCSIISessionManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return  # Already initialized, skip
        
        self._lock = threading.Lock()
        self._backend = None
        self._pin = None
        self._initialized = True
```

**Usage**:

```python
manager1 = get_session_manager()  # First call creates singleton
manager2 = get_session_manager()  # Second call returns same instance
assert manager1 is manager2  # True
```

**Thread Safety**:
- Class-level lock protects singleton creation
- Instance lock protects operations
- RLock (reentrant lock) allows same thread to acquire multiple times

### PIN Caching Strategy

**Goal**: Minimize PIN entry prompts (ideally one per application lifetime).

**Caching Locations** (Priority Order):

1. **Function Parameter**:
   ```python
   initialize_session(pin="123456")  # Explicit parameter
   ```

2. **Environment Variable**:
   ```bash
   export RNS_PKCS11_PIN="123456"
   python app.py
   ```

3. **Configuration File**:
   ```ini
   # ~/.config/reticulum/pkcs11_identity.conf
   pin = "123456"
   ```

4. **User Prompt** (if `auto_prompt=True`):
   ```python
   initialize_session(auto_prompt=True)
   # → getpass("Enter YubiKey PIN: ")
   ```

**In-Memory Caching**:

```python
self._pin = pin  # Stored in session manager for lifetime of session
# Accessed by all operations without re-prompting
```

**Lifecycle**:

```
App Starts
  ↓
initialize_session()
  ↓
PIN obtained (checked in priority order)
  ↓
Stored in _pin field
  ↓
Backend opened (logs in with PIN)
  ↓
PIN reused for all operations (no re-entry)
  ↓
App Stops
  ↓
PIN forgotten (not persisted if from prompt)
```

## Configuration Persistence

### File Format

**Location**: `~/.config/reticulum/pkcs11_identity.conf`

**Format**: INI-style

```ini
# PKCS#11 Hardware Identity Configuration
# Auto-generated - edit carefully

provider = "auto"
token_label = "YubiKey PIV"
pin = "123456"
pin_env = "RNS_PKCS11_PIN"
```

**Parsing** (in `config.py`):

```python
def _load(self):
    if not self.config_file.exists():
        return
    
    with open(self.config_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if "=" not in line:
                continue
            
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            
            # Remove quotes
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            
            self._data[key] = value
```

### App-to-Slot Mapping File

**Location**: `~/.config/reticulum/pkcs11_app_slots.conf`

**Format**:

```ini
# Auto-generated: app-to-PIV-slot mapping
# Format: app_name = slot
# Apps can share slots (comma-separated)

sideband = 9a
meshchat = 9c
custom_tool = 9d
```

**Parsing** (in `app_identity.py`):

```python
def _load_mapping(self):
    self._mapping.clear()
    self._slot_apps.clear()
    
    if not self.config_file.exists():
        return
    
    with open(self.config_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if "=" not in line:
                continue
            
            app, slots_str = line.split("=", 1)
            app = app.strip()
            
            # Parse slot(s)
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
```

## Provider Auto-Detection

### Fallback Chain

**Detection Order** (in `discovery.py`):

1. **Yubico libykcs11** (PIV on YubiKey)
   - Windows: `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`
   - Linux: `/usr/lib/x86_64-linux-gnu/libykcs11.so`

2. **OpenSC** (Generic smartcard support)
   - Windows: `C:\Program Files\OpenSC Project\OpenSC\opensc-pkcs11.dll`
   - Linux: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`

3. **SoftHSM2** (Software HSM for testing)
   - Windows: `C:\Program Files\SoftHSM2\bin\softhsm2.dll`
   - Linux: `/usr/lib/softhsm/libsofthsm2.so`

**Algorithm**:

```python
def get_default_provider() -> str:
    providers = discover_modules()
    if providers:
        return providers[0]  # Return first working provider
    raise PKCS11ProviderNotFoundError("No PKCS#11 providers found")

def discover_modules() -> list[str]:
    found = []
    for candidate in _DEFAULT_MODULE_CANDIDATES:
        try:
            lib = pkcs11.PyKCS11Lib()
            lib.load(candidate)  # Try to load
            found.append(candidate)
        except:
            pass  # Not available, continue
    return found
```

**Example Output**:

```
Windows:
  Found: C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll
  Skipped: C:\Program Files\OpenSC Project\... (not installed)

Linux:
  Found: /usr/lib/x86_64-linux-gnu/libykcs11.so
  Found: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
  Skipped: /usr/lib/softhsm/... (not installed)
```

**Performance**:
- First `discover_modules()` call: Tries all ~10 candidates
- Subsequent calls: Cached result
- Typical latency: 50-100 ms

## Error Recovery Patterns

### Pattern 1: Token Removal During Operation

**Scenario**:
```
1. initialize_session(pin="123456")  // Session opens
2. identity.sign(message)             // Session active
3. [User unplugs YubiKey]
4. identity.sign(message)             // Fails!
```

**Recovery Logic** (in `backend.py`):

```python
def sign(self, session, message):
    try:
        return session.sign(private_key, message, Mechanism(CKM_EDDSA))
    except PKCS11SessionError as e:
        if "token removed" in str(e).lower():
            # Token removed, try to recover
            self._session = None
            time.sleep(2)  # Wait for reinsertion
            
            try:
                session = self._open_session()  # Reopen
                return session.sign(private_key, message, Mechanism(CKM_EDDSA))
            except:
                raise PKCS11BackendError("Token removed and recovery failed")
```

### Pattern 2: PIN Locked

**Scenario**:
```
Three failed PIN attempts lock the card (YubiKey default).
```

**Detection**:

```python
def login(self, pin):
    try:
        session.login(pin)
    except pkcs11.exceptions.InvalidUserPIN:
        raise PKCS11LoginError("Incorrect PIN")
    except pkcs11.exceptions.PinLocked:
        raise PKCS11LoginError(
            "PIN locked. Reset with: ykman piv access change-pin"
        )
```

### Pattern 3: Partial Key Generation Failure

**Scenario**:
```
Ed25519 key generated, but X25519 generation fails midway.
Slot now has partial keys (inconsistent state).
```

**Prevention**:

```python
def ensure_keys_for_app(slot):
    session = self.open_session(slot)
    
    # Check if keys already exist
    ed_key = self.find_key(session, "Ed25519")
    x_key = self.find_key(session, "X25519")
    
    if ed_key and x_key:
        return  # Both present, nothing to do
    
    if ed_key and not x_key:
        # Partial state - this shouldn't happen
        # Log warning but continue (X25519 will be generated)
        pass
    
    # Generate missing keys
    if not ed_key:
        self.generate_key(session, "Ed25519")
    if not x_key:
        self.generate_key(session, "X25519")
```

## Debugging & Inspection Techniques

### Inspecting PKCS#11 Objects

**List all keys on a slot**:

```python
from reticulum_pkcs11_identity import get_backend
import pkcs11

backend = get_backend()
session = backend.open_session("9a")

# Find all objects
objects = session.findObjects()

for obj in objects:
    attrs = session.getAttributeValue(obj, [
        pkcs11.Attribute.CLASS,
        pkcs11.Attribute.LABEL,
        pkcs11.Attribute.ID,
    ])
    print(f"Object: {attrs}")
```

### Inspecting Token Info

**List token details**:

```python
from reticulum_pkcs11_identity import enumerate_tokens, discover_modules

providers = discover_modules()
for provider in providers:
    tokens = enumerate_tokens(provider)
    for token in tokens:
        print(f"Provider: {provider}")
        print(f"  Token: {token['label']}")
        print(f"  Model: {token['model']}")
        print(f"  Serial: {token['serial']}")
```

### Inspecting Key Format

**Verify key encoding**:

```python
from reticulum_pkcs11_identity import get_backend
import binascii

backend = get_backend()
session = backend.open_session("9a")

ed_pub = backend.get_public_key(session, "sign")
x_pub = backend.get_public_key(session, "enc")

print(f"Ed25519 public key ({len(ed_pub)} bytes):")
print(f"  Hex: {binascii.hexlify(ed_pub).decode()}")
print(f"  EC_POINT prefix: {binascii.hexlify(ed_pub[:2]).decode()}")
print(f"  Raw key: {binascii.hexlify(ed_pub[2:]).decode()}")

print(f"\nX25519 public key ({len(x_pub)} bytes):")
print(f"  Hex: {binascii.hexlify(x_pub).decode()}")
print(f"  EC_POINT prefix: {binascii.hexlify(x_pub[:2]).decode()}")
print(f"  Raw key: {binascii.hexlify(x_pub[2:]).decode()}")
```

**Expected Output**:
```
Ed25519 public key (34 bytes):
  Hex: 042078ab...
  EC_POINT prefix: 0420
  Raw key: 8ab...

X25519 public key (34 bytes):
  Hex: 042012cd...
  EC_POINT prefix: 0420
  Raw key: 12cd...
```

### Session Debugging

**Check session state**:

```python
from reticulum_pkcs11_identity import is_session_ready, get_session_manager

manager = get_session_manager()
print(f"Session ready: {manager.is_ready()}")
print(f"Backend: {manager.get_backend()}")
print(f"PIN cached: {manager._pin is not None}")
print(f"Provider: {manager._provider}")
```

---

## Performance Optimization Tips

### 1. Minimize Key Lookups

**Inefficient**:
```python
for i in range(100):
    pub = backend.get_public_key(session, "sign")  # 100 lookups!
```

**Efficient**:
```python
pub = backend.get_public_key(session, "sign")  # Once
for i in range(100):
    use(pub)  # Reuse
```

### 2. Batch Operations

**Inefficient**:
```python
for msg in messages:
    sig = identity.sign(msg)  # 100 separate operations
```

**Efficient**:
```python
session = backend.open_session("9a")  # Open once
for msg in messages:
    sig = session.sign(private_key, msg, mechanism)  # Reuse session
```

### 3. Cache Session Handles

**The system does this automatically** via singleton:
```python
# Session stays open for entire app lifetime
# All operations reuse the same session
# PIN entered once at startup
```

### 4. Async Signing

PKCS#11 operations are slow, consider async:
```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def sign_async(message):
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        return await loop.run_in_executor(
            executor,
            lambda: identity.sign(message)
        )
```

---

## Related Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — System design overview
- [API_REFERENCE.md](API_REFERENCE.md) — Public API functions
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — Common issues
