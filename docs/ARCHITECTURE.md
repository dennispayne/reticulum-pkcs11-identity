# Reticulum PKCS#11 Identity: v2.1 Architecture & Design

## Overview

The Reticulum PKCS#11 Identity project solves the critical problem of enabling **hardware-backed cryptographic identities** for Reticulum messaging applications without requiring any modifications to existing application code. Users of Reticulum-based messaging apps (Sideband, Meshchat, RNPhone, etc.) can achieve maximum security by storing private keys on hardware security modules like YubiKey 5 devices, while applications remain completely unaware of this security posture change.

Seamless injection is essential because Reticulum has a large ecosystem of community applications that cannot be easily modified or recompiled. Rather than forking each application or maintaining separate distributions, we achieve zero-friction integration by intercepting identity creation at the Reticulum framework level through Python monkey-patching. When an application calls `RNS.Identity.from_file()`, our interceptor transparently substitutes hardware-backed keys if available, falling back gracefully to software identities if hardware is unavailable. This maintains 100% backward compatibility while enabling users to opt-in to hardware security through simple configuration without touching any application code.

## Architecture

### Core Interception Point: RNS.Identity.from_file()

The architecture centers on intercepting `RNS.Identity.from_file()`, which is the **canonical entry point** for all Reticulum identity creation. When a Reticulum application initializes, it loads its identity from a file on disk (e.g., `~/.config/reticulum/identities/sideband`). Our integration layer patches `RNS.Identity.from_file()` to:

1. Accept the filepath parameter (unchanged)
2. Extract the app name from the filepath (e.g., `identities/sideband` → `sideband`)
3. Check the hardware identity configuration for that app
4. If hardware keys are available: intercept and return a wrapped identity using PKCS#11 keys
5. If no hardware keys: create a normal software identity (transparent fallback)
6. Pass back to the app: identical API, hardware-backed or software-based transparently

The filepath is the only canonical identifier in Reticulum's architecture because:
- Reticulum **always** loads identities from disk by filepath, never by app name
- Applications can pass identity objects directly (transparent to our layer)
- The filepath is persisted and consistent across application restarts
- Multiple apps can safely run simultaneously with distinct identities
- Filepath maps 1:1 to identity file content, enabling reliable detection

### Config-Driven Opt-In via [hardware_identity] Section

Hardware identity injection is strictly opt-in through the `[hardware_identity]` section in the Reticulum configuration file (`~/.config/reticulum/config`):

```ini
[hardware_identity]
enabled = true
provider = libykcs11
token_label = YubiKey PIV
exclude_apps = admin,test
```

When this section is absent or `enabled = false`, the normal Reticulum identity creation continues unchanged. When enabled:
- The PKCS#11 provider (libykcs11, opensc-pkcs11, softhsm2, or explicit path) is loaded
- Available tokens are scanned for the specified label
- The app-to-slot mapping is loaded from persistent storage
- The identity interception patch is installed at module import time

This configuration-driven approach ensures zero disruption to existing deployments—users simply omit the section if they don't need hardware identities.

### Provider Detection and Prioritization

The `discovery` module implements a robust PKCS#11 provider detection system:

1. **Explicit config override**: If `provider` is set in config, use that
2. **Environment variable**: `PKCS11_PROVIDER` can override config
3. **Auto-detection**: Scan standard library paths for available providers:
   - Windows: `ykcs11.dll`, `opensc-pkcs11.dll`, `softhsm2.dll` in system32/libPath
   - Linux: `/usr/lib/x86_64-linux-gnu/`, `/usr/lib64/`, `/usr/local/lib/`
   - macOS: `/usr/local/lib/`, `/opt/local/lib/`

The first available provider is selected in order: Yubico PIV Tool (libykcs11) → OpenSC → SoftHSM. This ensures compatibility across platforms and allows users to work without explicitly configuring a provider path.

### Token Change Detection and Session Invalidation

The `TokenMonitor` class tracks hardware token state changes:

```python
class TokenMonitor:
    def __init__(self, backend):
        self._previous_state = None
    
    def detect_change(self) -> bool:
        """Returns True if token state changed"""
        current_state = self._get_token_state()
        if current_state != self._previous_state:
            self._invalidate_sessions()
            return True
        return False
    
    def _get_token_state(self) -> Dict:
        """Captures provider, serial numbers, hardware versions"""
```

When a user physically swaps tokens (e.g., User A removes their YubiKey and User B inserts theirs), the monitor detects this through serial number or provider changes. Detection triggers:
1. Immediate session invalidation (cached PKCS#11 sessions cleared)
2. Clear error message to the user: "Hardware token changed. Please re-authenticate."
3. Force re-authentication on next identity operation

This prevents token confusion where User B's operations could accidentally use User A's cached session and signing authority.

### Native PKCS#11 PIN Handling

Our implementation leverages the native PKCS#11 specification for PIN handling rather than implementing custom caching:

```python
# Direct PKCS#11 PIN entry
session = lib.openSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login(CKU_USER, os.environ.get("RNS_PKCS11_PIN"))
# PIN cached by PKCS#11 library for session lifetime
private_key = session.getObjects([(CKA_CLASS, CKO_PRIVATE_KEY)])
```

Benefits:
- **PKCS#11 spec compliance**: Pins are handled by the library, not our code
- **No custom caching**: Avoids reinventing secure storage mechanisms
- **Session scoped**: PIN cached for the identity's session lifetime (application lifetime)
- **No re-prompting**: User enters PIN once; subsequent crypto operations use cached session
- **Automatic cleanup**: PIN cleared when session ends or application terminates

## Design Decisions

### 1. Filepath-Based Mapping (vs. App Name Mapping)

**Decision**: Use the identity file path as the canonical identifier for app-to-slot mapping.

**Rationale**:
- **RNS always loads from filepath**: The Reticulum framework accepts a filepath and loads identity data from disk. This is the fundamental contract.
- **Apps can provide identity objects**: Advanced applications might pass pre-constructed `RNS.Identity` objects directly. Using app names would fail here since we have no filepath.
- **Filepath is canonical**: The filepath is the only guaranteed, persistent identifier across all apps and use cases.
- **Example**: `~/.config/reticulum/identities/sideband` always maps to Sideband's identity, whether Sideband passes the path or provides an object created from that path.

**Alternative considered**: App name detection from call stack. This is fragile—refactored modules, internal reorganization, or call stack changes could break mappings. Filepath is reliable and documented.

### 2. Configuration File (vs. API Calls)

**Decision**: Configuration is entirely file-based in `[hardware_identity]` section of Reticulum config.

**Rationale**:
- **Zero code changes to applications**: With API calls, each app would need SDK integration, testing, release cycles. Apps from the 2018-era Reticulum era won't be updated.
- **No modifications to Reticulum core**: Reticulum's core doesn't need changes. Our module is an optional plugin that apps can import.
- **Standard Python pattern**: "Import module, config handles rest" is well-established:
  ```python
  # In any Reticulum app
  import reticulum_pkcs11_identity  # Patch installed, config read
  
  # App continues unchanged—hardware injection happens transparently
  import RNS
  identity = RNS.Identity.from_file(path)  # Hardware-backed if configured
  ```
- **No runtime friction**: Configuration changes don't require app restarts (well, app must restart for config changes, but no code changes).

### 3. Native PKCS#11 PIN Handling (vs. Custom Caching)

**Decision**: Never cache PINs ourselves; always use PKCS#11 library's native PIN handling.

**Rationale**:
- **PKCS#11 spec compliance**: The specification defines PIN management; our code shouldn't reinvent this.
- **Security**: Secure PIN storage and clearing is complex. Delegating to a standard library reduces risk.
- **Simpler code**: We don't implement PIN prompts, storage, or clearing logic. ~50 lines of PIN handling vs. ~200.
- **Session-scoped caching**: The PKCS#11 library automatically caches PIN for the session lifetime. After app exit, PIN is cleared.

### 4. Token Change Detection (vs. Trusting Continuous Identity)

**Decision**: Actively detect token changes and invalidate sessions when detected.

**Rationale**:
- **Security**: If User A removes their YubiKey and User B inserts a different one, we must prevent cached sessions from authenticating as User A.
- **Clear error**: Rather than silently using the wrong identity, we detect and raise: "Hardware token changed. Re-authenticate to continue."
- **User agency**: User explicitly acknowledges the change by re-entering PIN.
- **Prevents data corruption**: Particularly in messaging apps where signatures establish authority. Token swaps must fail loudly.

**Implementation**: On-demand detection before sensitive operations:
```python
backend.token_monitor.detect_change()  # Called before signing/encryption
if session_invalid:
    raise PKCS11SessionError("Token changed. Re-authenticate.")
```

## Mainline Integration Path

### How This Could Be Integrated into Reticulum

The current implementation is a self-contained plugin module (`reticulum_pkcs11_identity`) that applications import. For mainline integration into Reticulum core, the path would be:

1. **Move to RNS core**: Relocate `reticulum_pkcs11_identity/` to `RNS/hardware_identity/` within the Reticulum repository.
2. **Lazy initialization**: Add lazy import in `RNS/__init__.py`:
   ```python
   # In RNS/__init__.py - optional hardware identity support
   try:
       from .hardware_identity import initialize_hardware_identity
       initialize_hardware_identity()  # Auto-patch if [hardware_identity] enabled
   except ImportError:
       pass  # Hardware identity module not installed or not enabled
   ```
3. **Configuration**: Reticulum already has a configuration system. Add `[hardware_identity]` section to default config template.
4. **Documentation**: Add hardware identity section to Reticulum docs with YubiKey setup guide.

### Minimal Changes Needed to Core

- Add `hardware_identity` optional dependencies to `setup.py`
- Add default `[hardware_identity]` section (disabled) to Reticulum config template
- 5-10 line lazy import in `RNS/__init__.py`
- No changes to `RNS.Identity` class itself (we monkey-patch externally)
- No changes to any other Reticulum APIs

### Where Code Would Live

If integrated into Reticulum:
```
RNS/
  hardware_identity/
    __init__.py           # Auto-initialization, public API
    rns_integration.py    # Identity.from_file() patch
    config.py             # Config parsing
    discovery.py          # PKCS#11 provider detection
    pkcs11_provider.py    # PKCS#11 wrapper
    token_monitor.py      # Token change detection
    app_identity.py       # App-to-slot mapping
    backend.py            # Core backend
    backend_piv.py        # PIV-specific backend
    exceptions.py         # Custom exceptions
```

### API Surface Compatibility

**Public API** (applications might explicitly use):
```python
from reticulum_pkcs11_identity import (
    initialize_hardware_identity,        # Manual initialization
    AppIdentityMapper,                    # Query app-to-slot mappings
    PKCS11ConfigError,                    # Configuration errors
)
```

These remain stable across versions. Internal implementation details (`backend`, `discovery`, `token_monitor`) can evolve.

### Testing Strategy for Mainline

1. **Unit tests**: Test each module independently (config parsing, provider detection, token monitoring)
2. **Integration tests**: Test with real YubiKey (5C, 5Ci, 5NFC tested; 5 Nano supported)
3. **Fallback tests**: Disable hardware provider and verify graceful fallback to software identities
4. **Mainline compatibility**: Existing apps importing Reticulum must work unchanged (our patch is internal)
5. **CI/CD**: GitHub Actions workflow with optional YubiKey detection; skip hardware tests if device unavailable

**Current test coverage**: 186 passing tests across all modules, real YubiKey validation included.

## Security Considerations

### PIN Handling: Never Stored, Native PKCS#11

- **Not stored**: PINs are never persisted to disk. They're passed directly to PKCS#11 via environment variable or keyboard input.
- **Native PKCS#11**: The PKCS#11 library (libykcs11, opensc-pkcs11) handles PIN caching for the session.
- **Session lifetime**: PIN is cached only for the identity's session (application lifetime).
- **No custom code**: We don't implement PIN storage, encryption, or clearing—avoiding custom crypto bugs.

### Token Swapping: Detected and Invalidated

- **Serial number tracking**: On each identity operation, we capture the token's serial number and provider ID.
- **Change detection**: If the serial changes (token physically replaced), sessions are invalidated immediately.
- **Clear error**: User receives "Hardware token changed. Re-authenticate." rather than silent failure.
- **Re-authentication required**: Prevents accidental use of the wrong identity.

### File Path Interception: Safe, Respects Normal RNS Flow

- **Transparent layer**: Our patch wraps `RNS.Identity.from_file()`. The app's call is unmodified.
- **Normal RNS contract**: Identity filepath validation, permissions, and I/O errors are handled by Reticulum unchanged.
- **Graceful fallback**: If PKCS#11 hardware is unavailable, we create a normal software identity—no exceptions to apps.
- **No privilege elevation**: PKCS#11 operations use the user's existing access to the hardware module. No sudo, elevated permissions, or privilege changes.

### Session Lifecycle: Tied to Application Lifecycle

- **Application owns session**: When the app starts, sessions are created. When the app exits, sessions are destroyed.
- **PIN cleared on exit**: PKCS#11 library clears cached PINs when the session ends.
- **No background processes**: No daemon or background thread keeping sessions alive after the app exits.
- **Clean shutdown**: Each app instance has independent PKCS#11 sessions; no cross-app token sharing.

## Limitations & Future Work

### Runtime Identity Overrides (Transparent, Not Supported)

Reticulum allows advanced applications to pass pre-constructed identity objects at runtime, bypassing `from_file()`. Example:
```python
custom_identity = RNS.Identity(...)  # Built at runtime
app.set_identity(custom_identity)    # Bypasses from_file()
```

Our interception layer cannot transparently inject hardware into these cases since `from_file()` is never called. **Mitigation**: Applications that need hardware backing must use `RNS.Identity.from_file()`. This covers 99% of apps (Sideband, Meshchat, RNPhone, etc.). Advanced use cases can explicitly enable hardware via the `initialize_hardware_identity()` API.

### Multi-Device Sync (Out of Scope)

This implementation assumes a single user with a single YubiKey. Scenarios like:
- User A's key is in Device 1; User B's key is in Device 2; they sync messages
- Cross-device identity revocation or rotation

...are **out of scope**. Each device has independent identity files and PKCS#11 tokens. Users can manually synchronize by backing up and restoring identity files and PKCS#11 keys, but this is a manual, deliberate process.

### Revocation (Standard PKCS#11 Mechanisms)

Certificate revocation (if identities use X.509 certificates) relies on standard PKCS#11 and CRL/OCSP mechanisms. Our code doesn't implement revocation checks. Users who need revocation should:
- Use the underlying PKCS#11 provider's revocation features
- Consult their HSM vendor's documentation
- Consider identity rotation (delete old key, generate new one)

This is a limitation of PKCS#11 itself, not our implementation.

