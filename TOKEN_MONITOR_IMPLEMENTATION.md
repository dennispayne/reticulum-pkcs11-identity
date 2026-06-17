# Token Change Detection and Session Invalidation Implementation

## Overview
This document describes the implementation of token change detection and session invalidation for the PKCS#11 identity system (v2.1 feature).

## Components Implemented

### 1. TokenMonitor Class (`reticulum_pkcs11_identity/token_monitor.py`)
A new module that monitors PKCS#11 token state and detects changes.

#### Key Methods:
- **`get_provider_state()`**: Returns current provider and token state as a dictionary containing:
  - `provider_id`: Module path or name
  - `token_label`: Configured token label
  - `token_serials`: Set of available token serial numbers
  - `slot_ids`: Set of available slot IDs
  - `bound_fingerprint`: Current bound token fingerprint (if any)

- **`detect_changes()`**: Compares current state to previous state
  - Returns `(changed: bool, reason: Optional[str])`
  - Detects: token removal, token addition, serial changes, slot changes, provider changes
  - Stores state for comparison on next call

- **`invalidate_sessions()`**: Invalidates cached sessions when change detected
  - Closes backend session
  - Sets backend state to `SessionLifecycle.TOKEN_CHANGED`
  - Logs warning message

- **`check_and_invalidate()`**: Convenience method combining detection and invalidation
  - Returns `True` if change detected and sessions invalidated
  - Returns `False` if no change

- **`set_on_token_change_callback(callback)`**: Optional callback invoked on change

#### Thread Safety:
- All operations protected by internal `RLock`
- Safe for concurrent access

### 2. Backend Integration (`reticulum_pkcs11_identity/backend.py`)
- Added `_token_monitor` instance variable to `PKCS11Backend.__init__`
- Added `get_token_monitor()` method for lazy creation of monitor
- Monitor is created on first access, then reused

### 3. Identity Integration (`reticulum_pkcs11_identity/identity.py`)
Modified `HardwareIdentity` class (created by `make_lxmf_identity_class`):

- **`_check_token_state()` method**: Called before cryptographic operations
  - Checks for token changes via monitor
  - Raises `RuntimeError` if change detected with guidance message
  - Gracefully handles logging if RNS module not available

- **Modified `sign()` method**: Now calls `_check_token_state()` before signing
  - Detects token swap before performing cryptographic operation

- **Modified `decrypt()` method**: Now calls `_check_token_state()` before ECDH
  - Detects token swap before deriving shared secret

## Usage Pattern

### For Applications
No changes needed - token monitoring is transparent. If a token swap occurs:

```python
# Before token swap
identity.sign(message)  # Works normally

# After token swap (during use)
# On next operation:
identity.sign(message)  # Raises RuntimeError: "PKCS#11 token has changed..."
# App should catch error and prompt user to re-authenticate
```

### For Library Users
Can explicitly check token state:

```python
backend = create_backend(...)
backend.open_session(pin="1234")

# ... do operations ...

# Check for token changes
monitor = backend.get_token_monitor()
changed, reason = monitor.detect_changes()
if changed:
    print(f"Token changed: {reason}")
    # Invalidate and re-authenticate
    monitor.invalidate_sessions()
```

## Expected Behavior

### Scenario: Token Swap
1. User A has token with identity on slot PIV:9C
2. Application running, session established and open
3. User A unplugs token, User B plugs different token
4. On next identity operation (sign/decrypt):
   - Monitor detects change: "Token(s) removed: SERIAL-123"
   - Sessions invalidated (closed, state → TOKEN_CHANGED)
   - Operation raises: "PKCS#11 token has changed. Please re-authenticate with PIN or physical card."
5. User B must re-authenticate with their PIN
6. Application continues with User B's identity

### Token Change Detection
Detects:
- Token removal
- Token addition
- Serial number changes
- Slot availability changes
- Provider changes

## Error Handling

When token change is detected during operation:
- Clear warning logged: "Token change detected: [reason]"
- Session closed and marked as `SESSION_LIFECYCLE.TOKEN_CHANGED`
- User-facing error: "Token changed. Re-authenticate with PIN or physical card."
- Application can catch `RuntimeError` and handle appropriately

## Testing

### Test Coverage
- 14 unit tests in `tests/test_token_monitor.py`
  - State capture and change detection
  - Token addition/removal/serial changes
  - Session invalidation
  - Thread safety
  - Lazy instantiation

- 6 integration tests in `tests/test_token_monitor_integration.py`
  - Token state checks in identity operations
  - Sign operation token detection
  - Decrypt operation token detection
  - Session invalidation on change

### Test Results
- 199 tests pass (75 skipped due to missing SoftHSM2)
- All 20 token monitor tests pass
- No existing tests broken

## Implementation Notes

### Design Decisions
1. **Polling vs Background Thread**: Uses polling approach (check on each operation)
   - Simpler to implement and test
   - No background thread overhead
   - Suitable for v2.1 requirements

2. **Graceful Degradation**: If RNS logging not available
   - Logs to Python logger instead
   - Doesn't break if RNS module absent

3. **Thread-Safe**: All operations protected by internal lock
   - Safe for concurrent access
   - Compatible with multi-threaded applications

4. **Lazy Initialization**: Monitor created only when needed
   - No overhead if token monitoring not used
   - Created on first `get_token_monitor()` call

## Future Enhancements
- Optional background thread for continuous monitoring
- Configurable monitoring frequency
- Callback system for application-specific handling
- Integration with session manager for automatic recovery
- Support for multiple tokens and automatic failover
