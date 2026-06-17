# reticulum-pkcs11-identity - Multi-App Hardware Identity

**Hardware-backed identities for Reticulum user apps** (Sideband, Meshchat, RNPhone, etc.)

**Core Principle: Zero App Changes**. Apps call one function and either get a hardware identity or fall back to software. Transparent, automatic, no configuration needed in the app code.

## What Changed (from v1.0)

| Feature | v1.0 (LXMF-only) | v2.0 (Multi-app) |
|---------|---|---|
| **Target** | LXMF identity only | Any Reticulum user app |
| **Identities** | One hardware identity | One per app (optional sharing) |
| **Slots** | Single slot | 4 slots (9a, 9c, 9d, 9e) |
| **Allocation** | Manual config | First-come-first-served |
| **App changes** | Required | **Zero** |
| **Config** | Per-app | Global + auto-allocation |

## Architecture: PIV Slots for Multi-App Support

YubiKey PIV application has 4 usable slots:

```
Slot 9a (AUTHENTICATION)   → Sideband identity
Slot 9c (SIGNATURE)        → Meshchat identity
Slot 9d (KEY_MANAGEMENT)   → RNPhone identity
Slot 9e (CARD_AUTH)        → Reserved/future app
```

Each slot holds:
- One **Ed25519** key (for signing)
- One **X25519** key (for ECDH key exchange)

Apps can optionally **share slots** (e.g., RNPhone uses Meshchat's identity).

## Installation

```bash
pip install reticulum-pkcs11-identity
```

### Requirements

- **YubiKey** with PIV application (firmware 5.0+)
- **Windows**: Yubico PIV Tool (libykcs11.dll)
- **Linux**: OpenSC (opensc-pkcs11.so)
- **Python**: 3.9+

## Zero-Config Setup

### 1. Set PIN (one-time)

```bash
# Option A: Environment variable
export RNS_PKCS11_PIN=123456

# Option B: Config file (~/.config/reticulum/pkcs11_identity.conf)
echo 'pin = "123456"' > ~/.config/reticulum/pkcs11_identity.conf
```

### 2. Apps Just Work

No app code changes needed! Apps automatically use hardware:

```python
from reticulum_pkcs11_identity import get_or_create_hardware_identity

# In app's identity initialization code:
hw_identity = get_or_create_hardware_identity("sideband")

if hw_identity:
    # Use hardware
    ed_public, x_public = hw_identity.get_public_keys()
    # Create RNS.Identity with these keys, override sign()
else:
    # Fall back to software (as usual)
    identity = create_software_identity()
```

That's it. No config files, no manual slot allocation, no app-specific setup.

## How It Works

### First App (Sideband)

```
User runs Sideband
  ↓
get_or_create_hardware_identity("sideband")
  ↓
  ✓ PIN found (env var or config)
  ✓ YubiKey detected
  ✓ Slot 9a available
  ↓
Allocate: sideband → slot 9a
Generate Ed25519 + X25519 keys in 9a
Persist mapping in ~/.config/reticulum/pkcs11_app_slots.conf
  ↓
Return HardwareIdentity → Sideband uses it
```

Mapping saved:

```ini
# ~/.config/reticulum/pkcs11_app_slots.conf
sideband = 9a
```

### Second App (Meshchat)

```
User runs Meshchat (YubiKey still plugged in)
  ↓
get_or_create_hardware_identity("meshchat")
  ↓
  ✓ Check mapping: meshchat not in 9a, 9c, 9d
  ✓ Find first available: 9c is free
  ↓
Allocate: meshchat → slot 9c
Generate keys in 9c
Persist mapping
  ↓
Return HardwareIdentity → Meshchat uses it
```

Mapping updated:

```ini
sideband = 9a
meshchat = 9c
```

### Optional: App Sharing

RNPhone can explicitly share Meshchat's slot (same identity):

```python
from reticulum_pkcs11_identity import AppIdentityMapper

mapper = AppIdentityMapper()
mapper.share_slot("9c", "rnphone")  # RNPhone uses Meshchat's identity
```

## Configuration

### Environment Variables

```bash
# PIN (required for hardware)
export RNS_PKCS11_PIN=123456

# PKCS#11 provider (optional, auto-detected if not set)
export RNS_PKCS11_PROVIDER=/usr/lib/libykcs11.so
```

### Config File

Create `~/.config/reticulum/pkcs11_identity.conf`:

```ini
# PKCS#11 provider (auto-detect if set to "auto")
provider = auto

# YubiKey PIN
pin = "123456"

# Or use environment variable fallback
pin_env = RNS_PKCS11_PIN

# Token label (optional, for multi-token setups)
token_label = "YubiKey PIV #12345"
```

### App-to-Slot Mapping

Automatically managed in `~/.config/reticulum/pkcs11_app_slots.conf`:

```ini
# Auto-generated
sideband = 9a
meshchat = 9c
rnphone = 9c        # Can share with meshchat
rngit = 9d
```

## API Reference

### For App Developers (Recommended)

```python
from reticulum_pkcs11_identity import (
    get_or_create_hardware_identity,
    get_app_hardware_slot,
    is_app_using_hardware,
)

# Get or create hardware identity
hw_identity = get_or_create_hardware_identity("app_name")

if hw_identity:
    # Get public keys
    ed_pub, x_pub = hw_identity.get_public_keys()
    
    # Sign a message
    signature = hw_identity.sign(message)
    
    # Get ECDH public key
    ecdh_key = hw_identity.ecdh_public_key()

# Query status
slot = get_app_hardware_slot("sideband")  # Returns "9a" or None
is_using = is_app_using_hardware("meshchat")  # Returns True/False
```

### For Admin/Discovery

```python
from reticulum_pkcs11_identity import (
    list_all_app_slots,
    AppIdentityMapper,
    discover_providers,
    get_default_provider,
)

# See all mappings
slots = list_all_app_slots()  # {"sideband": "9a", "meshchat": "9c", ...}

# Advanced: mapper control
mapper = AppIdentityMapper()
available_slot = mapper.allocate_slot_for_app("new_app")  # "9d"
mapper.share_slot("9a", "existing_app")  # Share slot 9a
mapper.unmap_app("sideband")  # Remove mapping

# Discover PKCS#11 providers
providers = discover_providers()  # ["/usr/lib/libykcs11.so", ...]
provider = get_default_provider()  # Auto-detect best option
```

## Examples

See `examples/` directory:

- `sideband_identity.py` – How Sideband integrates
- `generic_app_setup.py` – Generic pattern for any app

## Troubleshooting

### "No PKCS#11 provider found"

Install Yubico PIV Tool or OpenSC:

```bash
# Windows
choco install yubico-piv-tool
# or download from https://developers.yubico.com/yubico-piv-tool/

# macOS
brew install yubico-piv-tool opensc

# Linux (Ubuntu/Debian)
sudo apt-get install opensc
```

### "PIN not configured"

Set PIN via environment variable or config:

```bash
export RNS_PKCS11_PIN=123456
```

Or create config file `~/.config/reticulum/pkcs11_identity.conf`:

```ini
pin = "123456"
```

### "All slots in use"

Up to 4 apps can use hardware simultaneously (one per slot). If you need more:
- Configure apps to share slots (optional, advanced)
- Or remove app mapping: `mapper.unmap_app("old_app")`

### "Hardware identity not available"

This is **expected and fine**. The app will fall back to software identity.

Reasons hardware might be unavailable:
- YubiKey not plugged in
- PIN not configured
- No compatible PKCS#11 provider installed

## Design Decisions

### Why PIV Slots?

- **Standard**: Defined by NIST, not Yubico-specific
- **Hardware-agnostic**: Works on any card with PIV (not just YubiKey)
- **Conservative**: Each app gets its own isolated key pair
- **Scalable**: 4 slots = 4 independent identities

### Why First-Come-First-Served?

- **Simple**: No config needed
- **Natural**: User plugs in YubiKey, first app to request identity gets first slot
- **User-friendly**: No admin burden
- **Flexible**: Apps can share slots if desired (advanced use case)

### Why Zero App Changes?

- **Adoption**: Sideband, Meshchat, etc. don't need forks or patches
- **Compatibility**: Hardware is optional, software fallback always works
- **Future-proof**: If new Reticulum identities emerge, they just call `get_or_create_hardware_identity()`

## Technical Details

### PKCS#11 / PIV Implementation

- Ed25519 signing: `CKM_EDDSA`
- X25519 ECDH: `CKM_ECDH1_DERIVE` with SHA256 KDF
- Key generation: On-device (hardware generates keys, never exported)
- Key extraction: Public keys extracted via PKCS#11, private keys stay in hardware

### Supported Hardware

- **YubiKey 5 series** (tested: 5C Nano)
- **YubiKey NEO+** (with firmware 3.3.0+)
- **Any PIV-capable smart card** (theoretical support via OpenSC)

### Tested On

- Windows 11 (libykcs11.dll from Yubico PIV Tool)
- Ubuntu 22.04 (opensc-pkcs11.so)

## License

See LICENSE file. This project includes contributor license terms.

---

**Questions?** See [examples/](examples/) or open an issue.
