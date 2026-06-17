# Reticulum PKCS#11 Identity - Troubleshooting

Comprehensive guide to diagnosing and resolving common issues with hardware identity setup and operation.

---

## Issue 1: "No PKCS#11 module found"

**Error Message**:
```
PKCS11ProviderNotFoundError: No PKCS#11 providers found
```

**Cause**:
- Yubico PIV Tool not installed
- OpenSC not installed
- SoftHSM2 not installed
- PKCS#11 libraries not in system PATH

**Diagnosis**:

```bash
# Check available providers
python -c "from reticulum_pkcs11_identity import discover_modules; print(discover_modules())"
# Output: [] (empty list)
```

**Resolution**:

**Option 1: Install Yubico PIV Tool** (Recommended for YubiKey):

*Windows*:
1. Download from: https://developers.yubico.com/yubico-piv-tool/Releases/
2. Install .msi file
3. Default path: `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`

*Linux (Ubuntu/Debian)*:
```bash
sudo apt-get install yubico-piv-tool libykcs11-1
```

*macOS*:
```bash
brew install yubico-piv-tool
```

**Option 2: Install OpenSC** (For generic smartcard support):

*Windows*:
1. Download from: https://github.com/OpenSC/OpenSC/releases
2. Install .msi file
3. Default path: `C:\Program Files\OpenSC Project\OpenSC\opensc-pkcs11.dll`

*Linux (Ubuntu/Debian)*:
```bash
sudo apt-get install opensc
# Default: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

**Option 3: Use SoftHSM2** (For development/testing):

*Windows*:
```powershell
# Install via chocolatey
choco install softhsm2
```

*Linux (Ubuntu/Debian)*:
```bash
sudo apt-get install softhsm2
```

**Verification**:
```bash
# After installing, re-run discovery
python -c "from reticulum_pkcs11_identity import discover_modules; print(discover_modules())"
# Should now show: ['/path/to/provider.dll'] or similar
```

**Workaround** (if providers unavailable):
Use software identity only (no hardware backing):
```python
identity = RNS.Identity()  # Software fallback
```

---

## Issue 2: "PIN prompt appears repeatedly"

**Symptom**:
User is prompted for PIN multiple times during application operation.

**Cause**:
- Session manager not initialized at startup
- `initialize_session()` not called
- New session opened for each operation
- PIN not cached

**Diagnosis**:

```bash
# Check if session manager is ready
python -c "from reticulum_pkcs11_identity import is_session_ready; print('Ready:', is_session_ready())"
# Output: Ready: False (BAD)
```

**Resolution**:

Ensure `initialize_session()` is called **once** at node startup:

```python
# ✓ CORRECT
from reticulum_pkcs11_identity import initialize_session, enable_hardware_identity_injection

# Call once at startup
if initialize_session(pin="123456"):
    enable_hardware_identity_injection()
    print("Session ready, no more PIN prompts")

# Now all operations reuse same session
identity = RNS.Identity()  # No PIN prompt here
message_sent = send_lxmf()  # No PIN prompt here
```

**Alternative: Use Environment Variable**

```bash
# Provide PIN via environment (avoids prompt)
export RNS_PKCS11_PIN="123456"
python app.py
```

**Verify Fix**:
```bash
# Should show "Ready: True" after initialize_session()
python -c "
from reticulum_pkcs11_identity import initialize_session, is_session_ready
initialize_session(pin='123456')
print('Ready:', is_session_ready())
"
# Output: Ready: True
```

---

## Issue 3: "YubiKey not detected"

**Error Message**:
```
PKCS11SessionError: No PKCS#11 tokens found
```

**Symptom**:
YubiKey is plugged in but not recognized by PKCS#11 library.

**Cause**:
- YubiKey not plugged in properly
- USB connection issue
- YubiKey PIV app disabled
- libykcs11 not loaded correctly
- Wrong PKCS#11 provider

**Diagnosis** (Step-by-step):

```bash
# 1. Check USB connection
# Windows: Check Device Manager → Ports (COM & LPT) → YubiKey
# Linux: lsusb | grep Yubico
# macOS: ioreg | grep -i yubico

# 2. Check if YubiKey is recognized by Yubico tool
ykman list
# Output: YubiKey 5 [0] OTP+FIDO+CCID

# 3. Check PIV applet
ykman piv info
# Output: PIV version: 3.0
#         PIN tries remaining: 3
```

**Resolution**:

**Step 1: Physical Connection**
- Unplug YubiKey
- Wait 5 seconds
- Plug back in firmly
- Verify it appears in `ykman list`

**Step 2: Enable PIV Applet** (if disabled):
```bash
# Reset PIV to default state
ykman piv reset

# Output:
# WARNING: This will delete all stored keys and certificates on this YubiKey!
# Proceed? [y/N]: y
# PIV applet reset successfully.
```

**Step 3: Verify Provider**
```python
from reticulum_pkcs11_identity import discover_modules, enumerate_tokens

# Find available providers
providers = discover_modules()
print(f"Found providers: {providers}")

# Enumerate tokens
for provider in providers:
    tokens = enumerate_tokens(provider)
    print(f"\nProvider: {provider}")
    for token in tokens:
        print(f"  Token: {token['label']}")
        print(f"  Serial: {token['serial']}")
```

**Step 4: Verify Session**
```python
from reticulum_pkcs11_identity import initialize_session

# Try to initialize with YubiKey
if initialize_session(pin="123456"):
    print("Success! YubiKey detected and session open")
else:
    print("Failed to initialize session")
```

**Workaround** (if YubiKey unavailable):
Applications automatically fall back to software identity:
```python
# initialize_session() returns False if hardware unavailable
# Apps automatically use software keys
identity = RNS.Identity()  # Software identity
```

---

## Issue 4: "Slot already occupied"

**Error Message**:
```
SlotNotFoundError: No available PIV slots. All 4 slots are in use.
```

**Cause**:
- All 4 PIV slots (9a, 9c, 9d, 9e) are allocated to apps
- 5th or more app trying to create hardware identity
- Slot not revoked after app uninstalled

**Diagnosis**:

```bash
# Check current slot usage
python -c "
from reticulum_pkcs11_identity import list_available_slots, find_app_slot

available = list_available_slots()
print(f'Available slots: {available}')

# List all app mappings
from reticulum_pkcs11_identity.app_identity import AppIdentityMapper
mapper = AppIdentityMapper()
print(mapper)
"
# Output:
# Available slots: []
# AppIdentityMapper:
#   9a (AUTHENTICATION): sideband
#   9c (SIGNATURE): meshchat
#   9d (KEY_MANAGEMENT): custom_tool
#   9e (CARD_AUTHENTICATION): legacy_app
```

**Resolution**:

**Option 1: Revoke Unused App Mapping**

```bash
# Remove old app that's no longer used
python -c "
from reticulum_pkcs11_identity import revoke_app_mapping

# This frees up the slot (keys remain on YubiKey)
old_slot = revoke_app_mapping('legacy_app')
print(f'Freed slot {old_slot} from legacy_app')
"
```

**Option 2: Share Slot Between Apps**

If two apps can use the same keys:
```python
from reticulum_pkcs11_identity.app_identity import AppIdentityMapper

mapper = AppIdentityMapper()
mapper.share_slot("9c", "new_app")  # new_app shares 9c with existing app
print(mapper)
# Output:
#   9c (SIGNATURE): meshchat, new_app
```

**Option 3: Check and Clean Configuration**

```bash
# View mappings file
cat ~/.config/reticulum/pkcs11_app_slots.conf

# If corrupted or old entries present, clean it:
rm ~/.config/reticulum/pkcs11_app_slots.conf

# Next app startup will re-create it with current mappings
```

**Workaround**: New apps automatically fall back to software identity:
```python
# 5th app creating identity
identity = create_app_hardware_identity("fifth_app")
if identity is None:
    identity = RNS.Identity()  # Falls back to software
```

---

## Issue 5: "Hardware signing failed"

**Error Message**:
```
PKCS11BackendError: Signing operation failed
```

**Symptom**:
- `identity.sign()` fails
- Signing sometimes works, sometimes fails
- Intermittent failures

**Cause**:
- PIN locked (3+ failed attempts)
- Session expired or lost
- YubiKey removed during operation
- USB connection unstable
- Malformed message

**Diagnosis**:

```bash
# 1. Check PIN status
ykman piv info
# Output:
# PIN tries remaining: 3      ← OK
# PIN tries remaining: 1      ← Locked soon
# PIN tries remaining: 0      ← LOCKED!

# 2. Check if YubiKey still connected
ykman list
# Should show YubiKey

# 3. Check logs
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)

from reticulum_pkcs11_identity import initialize_session, create_app_hardware_identity
initialize_session(pin='123456')
identity = create_app_hardware_identity('test_app')
sig = identity.sign(b'Test message')
print(f'Signature: {sig.hex()}')
"
```

**Resolution**:

**Step 1: Verify PIN is Correct**
```bash
# Try PIN with ykman
ykman piv access change-pin --pin 123456 --new-pin 123456
# If this works, PIN is correct
```

**Step 2: Unlock PIN if Locked**
```bash
# If PIN locked (tries remaining = 0):
ykman piv access reset-pin --puk 12345678

# If PUK also locked, full reset:
ykman piv reset
# WARNING: This deletes all keys!
```

**Step 3: Reinitialize Session**
```python
from reticulum_pkcs11_identity import shutdown_session, initialize_session

# Close and reopen session
shutdown_session()
if initialize_session(pin="123456"):
    print("Session reinitialized")
```

**Step 4: Physical Check**
- Unplug YubiKey
- Wait 5 seconds
- Replug firmly
- Retry operation

**Workaround**: Automatically falls back to software signing:
```python
# If hardware signing fails, sign() returns None
# Apps can detect and use software fallback
try:
    signature = identity.sign(message)
except:
    # Use software identity
    software_identity = RNS.Identity()
    signature = software_identity.sign(message)
```

---

## Issue 6: "Configuration file not found or corrupted"

**Error Message**:
```
PKCS11ConfigError: Failed to load config
```

**Cause**:
- Config file corrupted
- Permission denied
- Invalid INI format
- Encoding issues

**Diagnosis**:

```bash
# Check config file
cat ~/.config/reticulum/pkcs11_identity.conf

# Check permissions
ls -la ~/.config/reticulum/pkcs11_identity.conf
# Output: -rw-r--r-- (should be readable by user)

# Check app slots mapping
cat ~/.config/reticulum/pkcs11_app_slots.conf
```

**Resolution**:

**Option 1: Reset Configuration**
```bash
# Delete config to reset
rm ~/.config/reticulum/pkcs11_identity.conf
rm ~/.config/reticulum/pkcs11_app_slots.conf

# Next startup will recreate with defaults
python -c "
from reticulum_pkcs11_identity import initialize_session
initialize_session(pin='123456')  # Prompts again, recreates config
"
```

**Option 2: Fix Permissions**
```bash
# Ensure config is readable/writable by user
chmod 600 ~/.config/reticulum/pkcs11_identity.conf
chmod 700 ~/.config/reticulum/
```

**Option 3: Manual Config Edit**
```bash
# Create valid config manually
cat > ~/.config/reticulum/pkcs11_identity.conf << EOF
# PKCS#11 Hardware Identity Configuration
provider = "auto"
pin = "123456"
pin_env = "RNS_PKCS11_PIN"
EOF
```

---

## Issue 7: "App name not detected"

**Symptom**:
- Hardware identity not injected even though hardware available
- Different app gets same identity/slot
- `RNS_APP_NAME` ignored

**Cause**:
- Call stack ambiguous (multiple app modules)
- App name detection logic failing
- `RNS_APP_NAME` env var not set or empty

**Diagnosis**:

```python
# Check detected app name
from reticulum_pkcs11_identity.rns_integration import _detect_app_name

app_name = _detect_app_name()
print(f"Detected app name: {app_name}")

# Check env var
import os
print(f"RNS_APP_NAME: {os.environ.get('RNS_APP_NAME', 'NOT SET')}")
```

**Resolution**:

**Option 1: Set Environment Variable** (Recommended)
```bash
export RNS_APP_NAME="sideband"
python app.py
```

**Option 2: Explicit Identity Creation**
```python
from reticulum_pkcs11_identity import create_app_hardware_identity

# Explicit app name (bypasses detection)
identity = create_app_hardware_identity("sideband")
if identity is None:
    identity = RNS.Identity()  # Fallback
```

**Option 3: Check Call Stack**
```python
import inspect

# Debug call stack
frame = inspect.currentframe()
depth = 0
while frame:
    module_name = frame.f_globals.get("__name__", "")
    print(f"Frame {depth}: {module_name}")
    frame = frame.f_back
    depth += 1
    if depth > 10:
        break
```

---

## Issue 8: "All operations are slow"

**Symptom**:
- Signing takes 2+ seconds per message
- Key retrieval takes multiple seconds
- Session initialization takes 30+ seconds (beyond PIN prompt)

**Cause**:
- USB 2.0 connection (slow, use USB 3.0)
- Network latency (if using remote HSM)
- PKCS#11 provider overhead
- Batch operations without session reuse

**Diagnosis**:

```python
import time
from reticulum_pkcs11_identity import initialize_session, is_session_ready

# Measure session initialization
start = time.time()
initialize_session(pin="123456")
print(f"Session init: {time.time() - start:.2f}s")

# Measure signing
if is_session_ready():
    from reticulum_pkcs11_identity import get_backend
    backend = get_backend()
    session = backend.open_session("9a")
    
    start = time.time()
    sig = backend.sign(session, b"Test message")
    print(f"Signing: {time.time() - start:.2f}s")
```

**Expected Timings**:
- Session init (with PIN entry): 5-10 seconds
- Session init (no PIN entry): 100-200 ms
- Signing: 20-50 ms
- Key retrieval: 10-20 ms

**Resolution**:

**Option 1: Use USB 3.0**
- YubiKey 5 supports USB 3.0 (10x faster than 2.0)
- Use USB 3.0 port if available
- Check: `ykman --version` shows USB device type

**Option 2: Cache Operations**
```python
# ✗ Slow: Re-fetch key 100 times
for i in range(100):
    pub = backend.get_public_key(session, "sign")

# ✓ Fast: Fetch once, reuse
pub = backend.get_public_key(session, "sign")
for i in range(100):
    use(pub)
```

**Option 3: Batch Operations**
```python
# ✗ Slow: 10 separate sign operations
for msg in messages:
    sig = identity.sign(msg)  # Each opens/closes session

# ✓ Fast: Reuse session
session = backend.open_session("9a")
for msg in messages:
    sig = backend.sign(session, msg, mechanism)
```

**Workaround**: Accept slower signing for better security:
- Hardware-backed signing is inherently slower than software
- Typical messaging app only signs a few times per minute
- Latency is negligible for async operations

---

## Issue 9: "Permission denied" when saving config

**Error Message**:
```
PKCS11ConfigError: Failed to save config: Permission denied
```

**Cause**:
- Config directory doesn't exist and can't be created
- Config file exists with restrictive permissions
- ~/.config/ directory has wrong permissions
- Running as different user than created config

**Diagnosis**:

```bash
# Check directory permissions
ls -ld ~/.config/reticulum/
# Output: drwx------ or drwxr-xr-x (depends on umask)

# Check file permissions
ls -l ~/.config/reticulum/pkcs11_identity.conf
# Output: -rw------- or -rw-r--r--

# Check which user owns it
stat ~/.config/reticulum/pkcs11_identity.conf | grep Uid
```

**Resolution**:

**Option 1: Fix Directory Permissions**
```bash
# Ensure config directory is writable by user
mkdir -p ~/.config/reticulum
chmod 700 ~/.config
chmod 700 ~/.config/reticulum

# OR with umask
umask 0077  # Restrictive
mkdir -p ~/.config/reticulum
```

**Option 2: Fix File Permissions**
```bash
# If file already exists
chmod 600 ~/.config/reticulum/pkcs11_identity.conf
chown $USER ~/.config/reticulum/pkcs11_identity.conf
```

**Option 3: Switch User**
```bash
# If running as different user, switch:
su - original_user
python app.py
```

**Option 4: Custom Config Location**
```python
# Use different config directory if home inaccessible
from reticulum_pkcs11_identity.config import PKCS11Config

config = PKCS11Config(config_file="/tmp/my_config.conf")
```

---

## Issue 10: "Multiple apps getting same identity"

**Symptom**:
- Sideband and MeshChat sign with same keys
- `find_app_slot()` returns same slot for different apps
- Identity hashes identical for different apps

**Cause**:
- App name detection failing for both apps
- `RNS_APP_NAME` set to same value
- Slot explicitly shared by configuration

**Diagnosis**:

```python
from reticulum_pkcs11_identity import find_app_slot, get_app_identity_keys

# Check slot mapping
slot1 = find_app_slot("sideband")
slot2 = find_app_slot("meshchat")
print(f"Sideband slot: {slot1}")
print(f"MeshChat slot: {slot2}")

if slot1 == slot2:
    print("ERROR: Apps sharing same slot!")
    
# Check keys
keys1 = get_app_identity_keys("sideband")
keys2 = get_app_identity_keys("meshchat")

if keys1 and keys2 and keys1 == keys2:
    print("ERROR: Apps have identical keys!")
```

**Resolution**:

**Option 1: Fix App Name Detection**
```bash
# Set explicit app names via environment
export RNS_APP_NAME="sideband"
python sideband.py &

export RNS_APP_NAME="meshchat"
python meshchat.py &
```

**Option 2: Revoke and Reallocate**
```python
from reticulum_pkcs11_identity import revoke_app_mapping, allocate_slot_for_app

# Remove incorrect mapping
revoke_app_mapping("sideband")

# Force reallocation
allocate_slot_for_app("sideband", slot="9c")  # Explicitly use 9c
allocate_slot_for_app("meshchat", slot="9a")  # Explicitly use 9a
```

**Option 3: Reset Configuration**
```bash
# Delete mappings and start fresh
rm ~/.config/reticulum/pkcs11_app_slots.conf

# Restart apps one at a time (each gets different slot)
python sideband.py  # Gets 9a
python meshchat.py  # Gets 9c (not 9a)
```

---

## Issue 11: "Provider loading fails on specific OS"

**Symptom**:
- Works on Linux but not Windows (or vice versa)
- Provider path hardcoded incorrectly
- 32-bit vs 64-bit mismatch

**Cause**:
- Wrong architecture (32-bit provider on 64-bit Python)
- Path separators (backslash vs forward slash)
- Provider not installed for this OS
- Environment variables not set

**Diagnosis**:

```python
import sys

print(f"Python: {sys.version}")
print(f"OS: {sys.platform}")
print(f"Bits: {sys.maxsize > 2**32 and '64-bit' or '32-bit'}")

# Check available providers
from reticulum_pkcs11_identity import discover_modules
print(f"Available providers: {discover_modules()}")
```

**Resolution**:

**Windows-Specific**:
```bash
# Install 64-bit Yubico PIV Tool
# Download: https://developers.yubico.com/yubico-piv-tool/Releases/
# Choose: yubico-piv-tool-3.x.x-win64.msi

# Verify install
dir "C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"
```

**Linux-Specific**:
```bash
# Install both architecture versions if needed
sudo apt-get install libykcs11-1:amd64  # 64-bit
sudo apt-get install libykcs11-1:i386   # 32-bit (if needed)

# Verify location
find /usr -name libykcs11.so* 2>/dev/null
```

**macOS-Specific**:
```bash
# Install via homebrew
brew install yubico-piv-tool

# Verify location
ls -la /usr/local/lib/*ykcs11* || echo "Not found, check brew installation"
```

---

## Issue 12: "YubiKey firmware too old"

**Error Message** (implied):
- Signing fails intermittently
- Ed25519 keys not supported
- X25519 keys not supported

**Cause**:
- YubiKey firmware older than 5.1.0
- EdDSA support added in firmware 5.1.0
- Old firmware may not support RFC 8032 Ed25519

**Diagnosis**:

```bash
# Check firmware version
ykman --version

# Output:
# YubiKey 5 [OTP+FIDO+CCID] Serial: 12345678
# Firmware: 5.4.3              ← Check this
# Serial:   12345678

# Firmware 5.1.0+ required for Ed25519
```

**Resolution**:

**Update Firmware**:
1. Connect YubiKey
2. Download YubiKey Manager from: https://www.yubico.com/support/download/yubikey-manager/
3. Launch YubiKey Manager GUI
4. Click "Firmware Upgrade" tab
5. Follow upgrade wizard

**Or via CLI**:
```bash
# Backup keys first (if needed)
ykman export-certificates backup.pem

# Upgrade
ykman info  # Shows upgrade option
```

**Workaround**: Use older hardware or software identity:
```python
# If firmware doesn't support Ed25519, fall back to software
identity = create_app_hardware_identity("app")
if identity is None:
    identity = RNS.Identity()
```

---

## Quick Reference: Common Solutions

| Problem | Quick Fix |
|---------|-----------|
| No PIN prompt, hardware not used | Run `initialize_session(pin="123456")` at startup |
| PIN prompted repeatedly | Ensure `initialize_session()` called once before identity creation |
| YubiKey not detected | `ykman list`, check USB connection, install libykcs11 |
| Slot exhausted | `revoke_app_mapping("old_app")` to free slot |
| Slow signing | Use USB 3.0, cache operations, batch if possible |
| Multiple apps same identity | Set `RNS_APP_NAME` explicitly, or reset config |
| Config permission denied | `chmod 700 ~/.config/reticulum/` |
| Wrong architecture | Install 64-bit provider for 64-bit Python |
| Firmware too old | Update YubiKey to 5.1.0+ via ykman |

---

## Getting Help

If issue not listed above:

**1. Enable Debugging**:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

from reticulum_pkcs11_identity import initialize_session
initialize_session(pin="123456")  # Logs detailed info
```

**2. Collect Diagnostics**:
```bash
ykman version
ykman piv info
python -c "from reticulum_pkcs11_identity import discover_modules; print(discover_modules())"
python -c "from reticulum_pkcs11_identity import is_session_ready, initialize_session; initialize_session(pin='123456'); print('Ready:', is_session_ready())"
```

**3. Check Existing Issues**:
- GitHub Issues: https://github.com/reticulum-project/reticulum-pkcs11-identity/issues

**4. Report New Issue**:
Include:
- Python version
- OS (Windows/Linux/macOS)
- YubiKey model and firmware
- Error message and full stack trace
- Output from diagnostic commands above

---

## Related Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — System design overview
- [API_REFERENCE.md](API_REFERENCE.md) — Public API functions
- [IMPLEMENTATION_DETAILS.md](IMPLEMENTATION_DETAILS.md) — Technical details
