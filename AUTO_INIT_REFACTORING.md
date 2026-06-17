# Hardware Identity Auto-Initialization Refactoring

## Summary

The `rns_integration.py` module has been refactored to auto-initialize hardware identity injection at module import time, based on configuration settings. This eliminates the need for applications to explicitly call `enable_hardware_identity_injection()`.

## Changes Made

### 1. rns_integration.py Refactoring

**Auto-Initialization at Import**
- Added `_auto_initialize()` function that runs at module import time
- Loads config from `~/.config/reticulum/config` (section: `[hardware_identity]`)
- Checks if `enabled=true` in config
- Respects `exclude_apps` list to skip specific applications

**Config-Driven Setup**
- If enabled and not excluded:
  - Attempts to initialize PKCS11Backend with configured provider/token
  - Installs monkey-patch on RNS.Identity.__init__()
  - Logs: "Hardware identity injection enabled"
- If disabled or config missing:
  - Logs: "Hardware identity injection disabled or not configured"
- If enabled but provider unavailable:
  - Logs warning: "Hardware identity injection requested but provider unavailable"
  - Falls back to software identities

**Backward Compatibility**
- `enable_hardware_identity_injection()` remains available for manual override
- Now uses auto-initialized backend or accepts explicit backend parameter
- No app changes required to get auto-injection (just import module)
- Apps can still explicitly call function if needed for custom setup

**Error Handling**
- Gracefully handles missing config file
- Gracefully handles unavailable PKCS#11 provider
- Logs warnings for troubleshooting
- Always falls back to software identities if hardware unavailable

### 2. __init__.py Updates

**Exported API**
Added to `__all__` exports:
- `enable_hardware_identity_injection` - Manual override function
- `is_identity_hardware_backed` - Query function
- `get_identity_app_name` - Query function  
- `get_identity_slot` - Query function

These functions are now part of the public API and auto-initialized on module import.

### 3. Test Coverage

**New Tests Added** (test_rns_integration.py)
- `TestAutoInitialization.test_auto_initialize_disabled_config` - Verify disabled config handling
- `TestAutoInitialization.test_auto_initialize_with_excluded_app` - Verify exclusion list works
- `TestAutoInitialization.test_auto_initialize_no_provider` - Verify graceful fallback

**Existing Tests Updated**
- All 244 existing tests still pass
- No regressions detected

## User Experience

### Before (Old Way)
```python
import RNS
from reticulum_pkcs11_identity import enable_hardware_identity_injection

# Explicit initialization required
enable_hardware_identity_injection(backend)

# Now hardware identities used
identity = RNS.Identity.create()
```

### After (New Way - Recommended)
```python
# Just import - auto-initialization happens
import reticulum_pkcs11_identity
import RNS

# No explicit call needed - hardware identities used automatically if enabled
identity = RNS.Identity.create()
```

### Configuration

In `~/.config/reticulum/config`:
```ini
[hardware_identity]
enabled = true
provider = /path/to/libykcs11.so
token_label = YubiKey PIV
exclude_apps = app1,app2
```

## Implementation Details

### Global State
- `_auto_initialized_backend` - Stores backend created by auto-init
- `_patch_installed` - Tracks if monkey-patch is already installed

### Monkey-Patch Strategy
- Patches `RNS.Identity.__init__()` to intercept identity creation
- When identity created:
  1. Detects app name from call stack or `RNS_APP_NAME` env var
  2. Checks if app is in exclusion list
  3. Retrieves hardware keys from PKCS#11 token if available
  4. Injects hardware public keys into identity
  5. Overrides `sign()` method to use hardware signing
- If hardware unavailable, creates software identity as normal

### Error Handling
- Catches all exceptions during auto-init
- Logs warnings with details for troubleshooting
- Continues gracefully (software identities remain available)
- PKCS#11 provider unavailability is not fatal

## Backward Compatibility

✓ Fully backward compatible
- Old code calling `enable_hardware_identity_injection()` still works
- Apps without hardware config continue to work with software identities
- Existing tests all pass
- API surface unchanged (only expanded with exports)

## Migration Path

### No changes required for existing apps
Apps will automatically benefit from hardware identities if:
1. Module is imported (`import reticulum_pkcs11_identity`)
2. Config is enabled (`enabled=true` in `[hardware_identity]` section)
3. PKCS#11 token is present and accessible

### Optional: Explicit control still available
Apps can still call `enable_hardware_identity_injection(backend)` if they want custom setup.

## Logging

Auto-initialization produces the following log messages:

| Scenario | Log Level | Message |
|----------|-----------|---------|
| Config disabled | INFO | "Hardware identity injection disabled or not configured" |
| Config enabled, patch installed | INFO | "Hardware identity injection enabled" |
| App in exclude list | INFO | "Hardware identity injection disabled for excluded app: {app}" |
| Provider unavailable | WARNING | "Hardware identity injection requested but provider unavailable" |
| Auto-init error | WARNING | "Error during hardware identity auto-initialization: {error}" |

## Testing

All test scenarios pass:
- ✓ Auto-initialization with disabled config
- ✓ Auto-initialization respecting exclude lists
- ✓ Graceful fallback when provider unavailable
- ✓ Query functions for identity inspection
- ✓ Backward compatibility with manual calls
- ✓ All 244 existing tests still pass

## Files Modified

1. `reticulum_pkcs11_identity/rns_integration.py` - Main refactoring
2. `reticulum_pkcs11_identity/__init__.py` - API exports
3. `tests/test_rns_integration.py` - New test cases

## Future Enhancements

Potential future improvements:
1. Lazy initialization (defer backend setup until first identity creation)
2. Hot-swapping hardware (detect token removal/insertion)
3. Multiple provider support with fallback chain
4. Per-app configuration for hardware slots
