# Testing with Hardware Tokens

The test infrastructure supports running tests against both SoftHSM2 (software) and real hardware tokens (YubiKey, etc.) through environment variable configuration.

## Quick Start

### Default: SoftHSM2 (CI/Safe Default)
```bash
# No environment variables needed - uses SoftHSM2 if available
pytest tests/ -v
```

### Hardware: YubiKey with User PIN
```bash
export PKCS11_TEST_TOKEN=hw
export PKCS11_TEST_PIN=123456
pytest tests/ -v
```

### Explicitly Select SoftHSM2
```bash
export PKCS11_TEST_TOKEN=softhsm
pytest tests/ -v
```

## Environment Variables

| Variable | Purpose | Example | Required |
|----------|---------|---------|----------|
| `PKCS11_TEST_TOKEN` | Token backend selection | `hw` or `softhsm` | No (auto-detect) |
| `PKCS11_TEST_PIN` | User PIN for hardware token | `123456` | Yes if `PKCS11_TEST_TOKEN=hw` |
| `PKCS11_TEST_LABEL` | Token label for hardware | Auto-detected | No (auto-detected) |
| `PKCS11_TEST_ADMIN_PIN` | Admin PIN (if needed) | `12345678` | No |

## How It Works

### Token Selection Priority

1. **Explicit Request**: If `PKCS11_TEST_TOKEN` is set:
   - `hw`: Use hardware token (requires PIN)
   - `softhsm`: Use SoftHSM2

2. **Auto-Detect** (default):
   - Prefer SoftHSM2 if available (safest option)
   - Fall back to hardware if SoftHSM2 unavailable AND PIN is set
   - Skip if neither is available

### Auto-Detection on Different Setups

**CI/Automated Tests** → Uses SoftHSM2 (always available on CI)

**Local Dev with Both Installed** → Uses SoftHSM2 by default (safer)
```bash
# Explicitly test against hardware
PKCS11_TEST_TOKEN=hw PKCS11_TEST_PIN=123456 pytest tests/
```

**Local Dev with Only Hardware** → Auto-detects YubiKey if PIN is set
```bash
# No explicit PKCS11_TEST_TOKEN needed
PKCS11_TEST_PIN=123456 pytest tests/
```

## Real-World Examples

### Windows: Test against YubiKey 5C Nano
```powershell
$env:PKCS11_TEST_TOKEN = "hw"
$env:PKCS11_TEST_PIN = "123456"
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

### Linux: Test against SoftHSM2 explicitly
```bash
export PKCS11_TEST_TOKEN=softhsm
python -m pytest tests/ -v
```

### Raspberry Pi: Auto-detect YubiKey
```bash
# If SoftHSM2 not installed but YubiKey plugged in with PIN set
export PKCS11_TEST_PIN=123456
python -m pytest tests/ -v
```

### Local Laptop: Test both sequentially
```bash
# Test against SoftHSM2
pytest tests/ -v

# Later, test against YubiKey
PKCS11_TEST_TOKEN=hw PKCS11_TEST_PIN=123456 pytest tests/ -v
```

## What Each Test Sees

### With SoftHSM2
- Temporary test token created at session start
- Fresh key pairs generated for each test run
- Token cleaned up after tests complete
- No persistent state

### With Hardware Token
- Connects to existing YubiKey
- Keys must already exist on token (or tests skip gracefully)
- Tests that try to generate keys will fail/skip on real hardware
- No modifications to existing keys

## Fixture Behavior

### `pkcs11_backend` Fixture
```python
@pytest.fixture(scope="session")
def pkcs11_backend(request):
    # Selects the token based on PKCS11_TEST_TOKEN (hw / softhsm / auto).
    # SoftHSM2 fixtures are pulled in lazily, so selecting hardware does NOT
    # spuriously skip with a "SoftHSM2 is not installed" message.
    # In hw mode the shared (generative) token suite skips cleanly and never
    # writes to the token, because YubiKey PIV cannot generate/hold the
    # Ed25519/X25519 keys these tests create. Yields an opened, authenticated
    # SoftHSM2 backend otherwise.
```

> **Zero-skip note:** A full, zero-skip token run requires a *software*
> (generative) token — install SoftHSM2 (Linux/CI, or SoftHSM2-for-Windows) and
> use `PKCS11_TEST_TOKEN=softhsm`. A YubiKey alone cannot run the generative
> token suite; real hardware is exercised by the dedicated tests under
> `tests/integration/hardware/`.

## Troubleshooting

### "PKCS11_TEST_TOKEN=hw but PKCS11_TEST_PIN not set"
```bash
# Add the PIN
export PKCS11_TEST_PIN=123456
pytest tests/
```

### "No hardware PKCS#11 provider found"
- Ensure YubiKey is plugged in
- Check libykcs11 is installed
- Verify with: `rnidstatus list-tokens`

### "SoftHSM2 is not installed"
- Install: `scripts/install_test_deps.sh`
- Or explicitly use hardware: `PKCS11_TEST_TOKEN=hw PKCS11_TEST_PIN=123456 pytest`

### Tests skip when I expected them to run
- Check PIN is correct: `echo $PKCS11_TEST_PIN`
- Verify token is available: `rnidstatus list-tokens`
- Enable verbose output: `pytest tests/ -vv`

## Security Notes

**Never commit PINs to code!** Always use environment variables:

```bash
# Good: PIN from environment
PKCS11_TEST_PIN=$MY_DEV_YUBIKEY_PIN pytest tests/

# Bad: PIN in code
# Do not do this! ❌
backend.open_session(pin="123456")
```

## CI Integration

GitHub Actions example:
```yaml
# .github/workflows/tests.yml
- name: Run tests with SoftHSM2
  run: python -m pytest tests/ -v
  # No env vars needed - auto-detects SoftHSM2

# For hardware testing (optional, requires self-hosted runner):
- name: Run tests with YubiKey
  if: runner.os == 'Linux' && contains(runner.labels, 'has-yubikey')
  env:
    PKCS11_TEST_TOKEN: hw
    PKCS11_TEST_PIN: ${{ secrets.YUBIKEY_PIN }}
  run: python -m pytest tests/ -v
```

## For Developers

When adding new tests:
```python
def test_my_feature(pkcs11_backend):
    # Works with both SoftHSM2 and hardware
    # Backend fixture auto-selects based on environment
    
    # For hardware-only tests, use a marker:
    @pytest.mark.hardware
    def test_yubikey_specific():
        # Only runs with PKCS11_TEST_TOKEN=hw
```

## Next Steps

1. **Local Testing**: Run against SoftHSM2 during dev
2. **Pre-commit**: Run `pytest tests/` to verify
3. **Hardware Testing**: Before shipping, test with `PKCS11_TEST_TOKEN=hw`
4. **CI**: Automated tests use SoftHSM2 by default
5. **Production**: Users test with their own YubiKey

---

**Example Test Run on Real Hardware:**
```
$ PKCS11_TEST_TOKEN=hw PKCS11_TEST_PIN=123456 pytest tests/ -v
...
================ 305 passed, 96 skipped, 35 warnings in 8.23s =================
```

The hardware tests run slower due to YubiKey communication, but verify the system works with real tokens.
