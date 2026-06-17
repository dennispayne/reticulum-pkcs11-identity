# reticulum-pkcs11-identity

Protect your Reticulum app identities with a hardware token—no coding required.

## What is this?

If you use Reticulum apps (like Meshchat, Sideband, or others), your app identities are normally stored as files on your computer. This module lets you move those identities onto a hardware token like a YubiKey, smartcard, or Nitrokey instead.

**The key benefit:** Your cryptographic keys never leave the hardware. Your computer can use those keys to sign messages and encrypt data, but the actual key material stays safe on the token. Even if your computer is compromised, your keys are protected.

**The best part:** Your apps work exactly the same. Nothing changes on your end. You plug in the token, enable this module, and your identities automatically start using the hardware.

## How does it work?

**Without this module:**
```
Your Computer → App → Identity File on Disk (vulnerable) → Sign Messages
```

**With this module:**
```
Your Computer → App → Hardware Token → Sign Messages
                          (keys protected)
```

When your app needs to sign a message or create an identity, this module intercepts that and routes it to your hardware token instead of using a file.

## Setup (for non-coders)

### Step 1: Install

**Windows:**
1. Install Python (if you don't have it already)
2. Open Command Prompt and run:
   ```
   pip install reticulum-pkcs11-identity
   ```

**macOS:**
1. Install Python (if you don't have it)
2. Install smart card support:
   ```
   brew install pcsc-lite
   ```
3. Open Terminal and run:
   ```
   pip install reticulum-pkcs11-identity
   ```

**Linux:**
1. Install dependencies (Ubuntu/Debian):
   ```
   sudo apt install python3-pip libpcsclite-dev
   ```
2. Install the module:
   ```
   pip3 install reticulum-pkcs11-identity
   ```

### Step 2: Configure

1. Plug in your hardware token (YubiKey, smartcard, etc.)
2. Locate your Reticulum config file:
   - **Windows:** `C:\Users\YourUsername\.reticulum\config`
   - **macOS/Linux:** `~/.reticulum/config`
   
3. Open the config file in a text editor and add this section (or update it if it exists):
   ```
   [hardware_identity]
   enabled = true
   ```
    
That's it. The module auto-detects your hardware token.

**Optional:** If you have multiple tokens or want to specify a particular provider:
```
[hardware_identity]
enabled = true
provider = libykcs11              # Leave blank to auto-detect
token_label = YubiKey PIV #12345  # Optional: specify which token
pin_env = MY_TOKEN_PIN            # Optional: read PIN from env var instead of prompting
```

### Step 3: Use your apps

Just run your Reticulum apps normally. The module intercepts identity creation and routes it to your hardware token automatically.

**To check the status:**
```bash
rnidstatus
```

This command works just like `rnstatus` or `rnsd`—it shows which identities are using hardware and which are still using files.

(Or use: `python -m reticulum_pkcs11_identity status`)

## How do I know it's working?

When you first run an app with hardware backing enabled:
1. The token prompts you for its PIN (this is normal)
2. The app creates your identity on the token (happens once per app)
3. Future runs don't need the PIN again (token caches it)
4. The `rnidstatus` command shows your app using hardware

If something goes wrong, you'll see clear error messages. The module is designed to be transparent—if hardware is unavailable or disabled, apps fall back to using local identity files (no data loss, nothing breaks).

## What if I need to switch tokens?

If you plug in a different hardware token on the same machine:
1. The module detects the change automatically
2. Apps wait for you to authenticate to the new token
3. If the new token has the same identities, everything just works
4. If it doesn't, you can move the identity file to the new token (manual process, but safe)

## Troubleshooting

**Token not detected:**
- Make sure it's plugged in
- Try: `rnidstatus`
- If still not working, you may need to install the token's drivers (e.g., Yubico PIV Tool for YubiKey)

**PIN prompts too often:**
- This is normal for new tokens—the PIN is cached after first use
- If you're still seeing prompts later, the session may have expired (intentional for security)

**App won't start:**
- Check the status command (see above)
- If hardware is having issues, the app automatically falls back to software identities
- No data is lost; you can always switch back

## Under the hood (optional reading)

This module uses PKCS#11, the universal standard for hardware cryptography. It's the same protocol used by:
- YubiKey
- Nitrokey
- Most smartcards
- Hardware security modules (HSMs)
- Software simulators like SoftHSM

This means one installation works with any compatible hardware. Not tied to a specific vendor or device.

**How seamless is it?** The module is installed as a Python package, but it works by being imported before your app runs. We recommend wrapping your app launch in a simple script or shell command that imports the module first. See "Integration" below.

## Integration with your apps

The module is designed to be **completely transparent** — apps don't need to change. But if you're an app developer and want to ensure hardware identity is active, here are your options:

### Option 1: User-controlled (recommended for most apps)

Users decide whether to enable hardware identity in their Reticulum config. Your app works unchanged regardless:

```ini
[hardware_identity]
enabled = true
```

Your app just runs normally—no imports, no changes needed.

### Option 2: Automatic via wrapper scripts

If your app has a launch script, you can import the module before starting the app:

**Bash/shell script (macOS/Linux):**
```bash
#!/bin/bash
python3 -c "import reticulum_pkcs11_identity" && python3 your_app.py
```

**Windows batch file:**
```batch
@echo off
python -c "import reticulum_pkcs11_identity"
python your_app.py
```

This ensures hardware identity is available without the user doing anything.

### Option 3: Direct import (if you control the entry point)

If you're building a Python app and control its entry point, add one line at the very top of your main module:

```python
import reticulum_pkcs11_identity  # Enable hardware identity, if configured

import RNS
# ... rest of your app code
```

This is the cleanest approach if you own the code. The import does nothing if hardware is disabled in the config, so it's safe and non-invasive.

### Why this design?

The module is **intentionally invisible** because:
- Apps continue working with or without hardware
- Users have full control via config file
- No vendor lock-in to specific providers
- Apps don't need updates when new hardware comes along
- Community can eventually adopt this into mainline Reticulum with minimal changes

## Is this safe?

Yes. This module:
- **Never stores or caches PINs** — Left to the hardware token
- **Never extracts private keys** — They stay on the device
- **Uses native PKCS#11 mechanisms** — Standard, widely audited protocols
- **Isolates each app's identity** — One app's keys can't access another's
- **Falls back gracefully** — If hardware fails, apps continue with software identities

The cryptography is handled entirely by the token. This computer just asks the token to sign things or encrypt data—it never sees the keys themselves.

## For developers

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Deep dive into how the module works, interception points, and design decisions
- **[INTEGRATION.md](docs/INTEGRATION.md)** — Path for integrating hardware identity support into mainline Reticulum

## License

MIT
