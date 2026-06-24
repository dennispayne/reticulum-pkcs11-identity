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
export PKCS11_TEST_TOKEN=yubikey
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
| `PKCS11_TEST_TOKEN` | Token backend selection | `yubikey` or `softhsm` | No (auto-detect) |
| `PKCS11_TEST_PIN` | User PIN for hardware token | `123456` | Yes if `PKCS11_TEST_TOKEN=yubikey` |
| `PKCS11_TEST_LABEL` | Token label for hardware | Auto-detected | No (auto-detected) |
| `PKCS11_TEST_ADMIN_PIN` | Admin PIN (if needed) | `12345678` | No |

## How It Works

### Token Selection Priority

1. **Explicit Request**: If `PKCS11_TEST_TOKEN` is set:
   - `yubikey`: Use hardware token (requires PIN)
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
PKCS11_TEST_TOKEN=yubikey PKCS11_TEST_PIN=123456 pytest tests/
```

**Local Dev with Only Hardware** → Auto-detects YubiKey if PIN is set
```bash
# No explicit PKCS11_TEST_TOKEN needed
PKCS11_TEST_PIN=123456 pytest tests/
```

## Real-World Examples

### Windows: Test against YubiKey 5C Nano
```powershell
$env:PKCS11_TEST_TOKEN = "yubikey"
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
PKCS11_TEST_TOKEN=yubikey PKCS11_TEST_PIN=123456 pytest tests/ -v
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
    # Selects the token based on PKCS11_TEST_TOKEN (yubikey / softhsm / auto).
    # SoftHSM2 fixtures are pulled in lazily, so selecting hardware does NOT
    # spuriously skip with a "SoftHSM2 is not installed" message.
    # In hw mode the shared (generative) token suite skips cleanly and never
    # writes to the token, to avoid leaving throwaway test keys on a real
    # device. (YubiKey 5.7+ firmware *can* hold Curve25519; the skip is about
    # not writing to your token, not capability.) Yields an opened,
    # authenticated SoftHSM2 backend otherwise.
```

> **Zero-skip note:** A full, zero-skip token run requires a *software*
> (generative) token — install SoftHSM2 on **Linux/CI/WSL** and use
> `PKCS11_TEST_TOKEN=softhsm`. SoftHSM2 on **Windows is not supported**: no
> Windows build implements Ed25519/X25519 (keygen fails with
> `MechanismInvalid`), so the generative suite skips cleanly on Windows by
> design. Run it under WSL instead (see *WSL: the software-token environment*
> below). The generative token suite is skipped on a real YubiKey to avoid
> writing throwaway keys to it (YubiKey 5.7+ does support Curve25519); real
> hardware is exercised by the dedicated tests under
> `tests/integration/hardware/`.

## Test layout

```
tests/
  unit/                     # pure-Python, no token; runs everywhere
  integration/
    software/               # SoftHSM2 generative suite (Linux/WSL/CI)
    hardware/               # real YubiKey; opt-in via PKCS11_TEST_TOKEN=yubikey
  e2e/                      # full Reticulum end-to-end
    _rns_peer.py            # standalone peer process (underscore = not collected)
    test_two_instance_e2e.py
```

## WSL: the software-token environment (Windows hosts)

On a Windows host the platform split is:

- **Software-token path → WSL/Linux/CI** (SoftHSM2, full Ed25519/X25519).
- **Hardware path → native Windows** (YubiKey via libykcs11).

Windows SoftHSM2 was evaluated and dropped: there is no winget package and no
Windows build supports Curve25519. Do **not** wire a Windows SoftHSM2 into
`conftest.py` — it would be discovered and then fail keygen with errors instead
of skipping.

### One-time WSL setup

```bash
# Ubuntu 24.04 under WSL2 ships SoftHSM2 2.6.1 at:
#   /usr/lib/softhsm/libsofthsm2.so   (full Ed25519 + X25519)
# Create an isolated venv (no sudo/compiler needed; wheels only):
python3 -m venv ~/rns_e2e
source ~/rns_e2e/bin/activate
pip install rns python-pkcs11 cryptography
pip install -e /mnt/c/Git/dennispayne/reticulum-pkcs11-identity
```

### Running the software-token suite under WSL

```bash
source ~/rns_e2e/bin/activate
cd /mnt/c/Git/dennispayne/reticulum-pkcs11-identity
export PYTHONPATH=$PWD
export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
# Use a Linux-native basetemp: SoftHSM file locks (flock) are unreliable on the
# /mnt/c DrvFs mount.
python -m pytest tests/integration/software tests/e2e \
  -o addopts="--basetemp=/tmp/rns_e2e_tmp -p no:cacheprovider"
```

> For best performance and clean file locks, clone the repo into the Linux
> filesystem (`~/...`) rather than running from `/mnt/c`.

## Two-instance loopback e2e

`tests/e2e/test_two_instance_e2e.py` proves a full first-launch flow: a
Reticulum app requests a new identity, that identity is routed to the token, and
two independent instances then exchange a real message.

- RNS Transport/destination tables are **process-global**, so the two instances
  run as **separate processes** — `_rns_peer.py` is launched twice via
  `subprocess`. Each peer uses an **isolated configdir** and talks over
  **loopback TCP** (server + client), independent of any Reticulum already
  running on the machine.
- Parametrized `software | softhsm`:
  - `software` (plain `RNS.Identity`) passes on **Windows and WSL** — validates
    orchestration.
  - `softhsm` makes **both** peers token-backed from a **single** SoftHSM token
    (separate sign/enc keys per node) — passes under **WSL** (skips on Windows).
- The client `identify()`s over the link (signed by the token key); the test
  asserts the identity hash the server captured on the wire matches the
  client's own, proving the token key signed the link proof.

### Token identities as link responders (`_TokenSigningKeyAdapter`)

RNS reads `identity.sig_prv` **directly** in `Link.__init__` (responder branch)
to derive the link signing pubkey and prove link packets. A hardware identity
has `sig_prv = None`, which crashed inbound link validation. `identity.py` adds
`_TokenSigningKeyAdapter`, set as `sig_prv` in both identity factories: it
exposes the real public key and routes signing through the token, so a
token-backed identity can **accept** links, not just initiate them.

## Troubleshooting

### "PKCS11_TEST_TOKEN=yubikey but PKCS11_TEST_PIN not set"
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
- Or explicitly use hardware: `PKCS11_TEST_TOKEN=yubikey PKCS11_TEST_PIN=123456 pytest`

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
    PKCS11_TEST_TOKEN: yubikey
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
        # Only runs with PKCS11_TEST_TOKEN=yubikey
```

## Next Steps

1. **Local Testing**: Run against SoftHSM2 during dev
2. **Pre-commit**: Run `pytest tests/` to verify
3. **Hardware Testing**: Before shipping, test with `PKCS11_TEST_TOKEN=yubikey`
4. **CI**: Automated tests use SoftHSM2 by default
5. **Production**: Users test with their own YubiKey

---

**Example Test Run on Real Hardware:**
```
$ PKCS11_TEST_TOKEN=yubikey PKCS11_TEST_PIN=123456 pytest tests/ -v
...
================ 305 passed, 96 skipped, 35 warnings in 8.23s =================
```

The hardware tests run slower due to YubiKey communication, but verify the system works with real tokens.
