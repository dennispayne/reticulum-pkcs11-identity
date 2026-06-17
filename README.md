# reticulum-pkcs11-identity

Seamless PKCS#11 hardware token support for Reticulum user app identities.

## What

Reticulum-pkcs11-identity brings hardware-backed cryptographic identities to any Reticulum app—without code changes. Use your YubiKey, smartcard, or SoftHSM to secure app identities with zero friction. Apps work unchanged; the module transparently injects hardware identity creation at import time. Each app uses its own dedicated PKCS#11 token slot, with secure PIN handling native to the token—never stored in memory or configuration.

Why PKCS#11? It's the universal standard for hardware cryptography. Works with YubiKey, Nitrokey, smartcards, and software simulators like SoftHSM. One implementation supports them all, making this a future-proof solution for hardware security.

## Why

**Design Philosophy:** Zero friction integration. No app rewrites, no imports, no configuration inside code. Just enable the module—identities use hardware automatically.

Designed for easy integration into mainline Reticulum if the community chooses to adopt it. The implementation requires minimal changes to RNS code paths.

**Security Model:** Native PIN handling leaves PINs with the token itself, never in memory or configuration files. Per-app slot isolation ensures one app's identity cannot leak another's cryptographic keys, providing defense-in-depth.

Works with any PKCS#11 provider (hardware or software) that supports Ed25519 and X25519 cryptographic operations—YubiKey PIV, Nitrokey, standard smartcards, SoftHSM, and more. Private keys never leave the device; only signatures and public keys traverse the software boundary.

## Install

```bash
pip install reticulum-pkcs11-identity
```

**Dependencies:**
- `python-pkcs11` — Python PKCS#11 bindings for hardware communication
- `libpcsclite` — Smart card reader service and communication layer

**Platform-specific installation:**
- **Linux:** `sudo apt install libpcsclite-dev` — Provides card reader support
- **macOS:** `brew install pcsc-lite` — Required for smart card access
- **Windows:** Uses native Windows libraries; install PKCS#11 provider separately (Yubico PIV Tool recommended for YubiKey)

## Configure

Add a `[hardware_identity]` section to `~/.config/reticulum/config`:

```ini
[hardware_identity]
enabled = true
provider = libykcs11
exclude_apps = debug_app, test_tool
```

**Configuration options:**
- `provider`: Auto-detected if omitted; explicitly set if multiple readers are present
- `exclude_apps`: Comma-separated app names to skip hardware injection (useful for testing)
- `enabled`: Set to `false` to disable without removing the configuration block

That's it. Zero app code changes required. The module handles everything else.

## Use

Import the module before RNS to enable transparent hardware identity injection:

```python
import reticulum_pkcs11_identity
import RNS

# App works normally; identities automatically use hardware
identity = RNS.Identity()
# ... continue as usual
```

That's all. The app has no awareness of the hardware layer. If hardware is unavailable, identities gracefully fall back to software.

**Check hardware status:**
```bash
python -m reticulum_pkcs11_identity status
```

## Design Intent

Seamless injection is intentional. The module monkey-patches at import time, allowing hardware support without touching app or Reticulum core code. This approach is designed so mainline Reticulum integration requires only minimal changes to identity creation paths—if the community decides that's the right direction.

Not intended to replace the core identity system. Rather, it provides a zero-friction way to plug in hardware security today, with a clean path to mainline inclusion later if desired. This design allows users to gain hardware security benefits immediately while keeping the door open for official integration.

## License

MIT
