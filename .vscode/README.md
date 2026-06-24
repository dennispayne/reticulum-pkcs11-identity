# VS Code Configuration for reticulum-pkcs11-identity

This directory contains VS Code configuration files for local development, debugging, and testing against both SoftHSM2 (software tokens) and YubiKey hardware tokens.

## Quick Start

1. **Install extensions** (recommended):
   - Click the "Extensions" icon in the Activity Bar
   - Search for "Python" and install `ms-python.python`
   - Click "Install" on the recommendation popup (or manually install recommended extensions)

2. **Copy environment template**:
   ```bash
   cp .vscode/.env.example .vscode/.env
   ```

3. **Configure for your testing environment**:
   ```bash
   # For SoftHSM2 (default, no config needed)
   # Just run tests

   # For YubiKey hardware testing:
   # Edit .vscode/.env and set:
   #   PKCS11_TEST_TOKEN=yubikey
   #   PKCS11_TEST_PIN=123456
   ```

## Key Files

### `settings.json`
Python interpreter, pytest configuration, type checking, and formatting settings.

- **Python Interpreter**: Points to `.venv\Scripts\python.exe` (or `.venv/bin/python` on Linux/macOS)
- **Pytest**: Enabled with verbose output by default
- **Type Checking**: Uses Pylance for fast, accurate language features

### `tasks.json`
Command palette tasks for running tests and CLI tools. Access with `Ctrl+Shift+B` or `Cmd+Shift+B`.

**Key tasks:**
- `Tests: Run all (SoftHSM2, default)` — Run all tests with SoftHSM2 (default test run)
- `Tests: Run all (quick, no verbose)` — Fast run (useful for CI feedback)
- `Tests: Run current file` — Test the file currently open in editor
- `Tests: Run selected node` — Test a specific test function or class (prompted)
- `Tests: Run with coverage` — Generate HTML coverage report
- `Tests: Run with YubiKey hardware` — Test against real hardware (requires PIN in .env)
- `CLI: List available PKCS#11 tokens` — Discover YubiKey and SoftHSM2 tokens
- `CLI: Show identity status` — Display current hardware identity configuration

**Run a task:**
1. Open Command Palette: `Ctrl+Shift+P` / `Cmd+Shift+P`
2. Type "Run Task" → select task → `Enter`

Or press `Ctrl+Shift+B` to run the default test task.

### `launch.json`
Debug configurations for running tests under the debugger. Access from the "Run and Debug" panel (`Ctrl+Shift+D`).

**Key configs:**
- `Pytest: All tests (SoftHSM2)` — Explicit SoftHSM2 (default)
- `Pytest: All tests (auto-detect)` — Auto-detect: SoftHSM2 → YubiKey fallback
- `Pytest: All tests (YubiKey hardware)` — Explicit hardware (requires PIN)
- `Pytest: Current file` — Debug the file currently open
- `Pytest: Current file (YubiKey hardware)` — Debug current file with hardware
- `Module: Show hardware token status` — Debug the token discovery CLI

**Start debugging:**
1. Open the "Run and Debug" panel: `Ctrl+Shift+D`
2. Select a configuration from the dropdown
3. Click the green "Start Debugging" button (or press `F5`)
4. The test will run with VS Code's debugger attached (breakpoints, step through code, etc.)

### `.env.example`
Template for environment variables. Copy to `.env` for local use.

**Test token selection:**
```bash
# SoftHSM2 (default, no config needed)
PKCS11_TEST_TOKEN=softhsm

# YubiKey hardware (requires PIN)
PKCS11_TEST_TOKEN=yubikey
PKCS11_TEST_PIN=123456
PKCS11_TEST_LABEL=YubiKey PIV #12345678  # optional, auto-detected
```

**Do NOT commit `.env`** — it contains your PIN! `.env.example` is committed as a template.

### `extensions.json`
Recommended VS Code extensions for this project.

**Recommended:**
- `ms-python.python` — Official Python support (required)
- `ms-python.vscode-pylance` — Type checking and completions
- `ryanluker.vscode-coverage-gutters` — Inline coverage display (if using `--cov`)
- `littlefoxteam.vscode-python-test-adapter` — Better pytest UI integration

To install all recommended extensions, click the "Extensions" icon and find "Recommended" tab.

## Workflows

### Development: Testing with SoftHSM2 (Default)

**1. Run tests on save (Recommended for TDD):**
- Tests run automatically when you save a file (configured in `settings.json`)
- See output in the "Test" panel on the left

**2. Run tests manually:**
- Command Palette → "Run Task" → "Tests: Run all (SoftHSM2, default)"
- Or press `Ctrl+Shift+B`

**3. Debug a test:**
- Open the test file in editor
- Click "Run and Debug" panel (left sidebar)
- Select "Pytest: Current file" → `F5`
- Set breakpoints, step through code, inspect variables

**4. Check coverage:**
- Command Palette → "Run Task" → "Tests: Run with coverage"
- Coverage gutters appear in the editor (green = covered, red = uncovered)
- Open `htmlcov/index.html` in browser for detailed report

### Hardware Testing: YubiKey Integration

**1. Set up environment:**
```bash
# Copy template
cp .vscode/.env.example .vscode/.env

# Edit .vscode/.env
# Set: PKCS11_TEST_TOKEN=yubikey
# Set: PKCS11_TEST_PIN=123456 (your YubiKey user PIN)
```

**2. Discover available tokens:**
- Command Palette → "Run Task" → "CLI: List available PKCS#11 tokens"
- Output shows detected YubiKey and SoftHSM2 tokens

**3. Run tests with hardware:**
- **Option A**: Run task → "Tests: Run with YubiKey hardware"
- **Option B**: Debug config → "Pytest: All tests (YubiKey hardware)" → `F5`
- Tests run against real YubiKey (slower, but validates hardware integration)

**4. Switch between backends:**
- Edit `.vscode/.env`: Change `PKCS11_TEST_TOKEN=softhsm` or `yubikey`
- Re-run tests
- No code changes needed

### CI/CD Validation

**Before pushing to GitHub:**
```bash
# Run all tests with SoftHSM2 (what CI uses)
ctrl+shift+p → "Run Task" → "Tests: Run all (SoftHSM2, default)"

# Or from terminal
.venv\Scripts\python.exe -m pytest tests/ -q
```

**Later, optional YubiKey validation:**
```bash
# Run all tests with YubiKey
ctrl+shift+p → "Run Task" → "Tests: Run with YubiKey hardware"

# Or set env var and run from terminal
$env:PKCS11_TEST_TOKEN = "yubikey"
$env:PKCS11_TEST_PIN = "123456"
.venv\Scripts\python.exe -m pytest tests/ -q
```

## Troubleshooting

### "Python interpreter not found"
- Ensure `.venv` exists: `uv venv` or `python -m venv .venv`
- Or open a terminal and manually activate: `.\.venv\Scripts\activate`
- Reload VS Code window: `Ctrl+Shift+P` → "Developer: Reload Window"

### "Pytest not found"
- Ensure test dependencies installed: `.\.venv\Scripts\python.exe -m pip install -e ".[test]"`
- Or run task: Command Palette → "Python: Install editable test deps"

### "YubiKey tests are skipping"
- Check `PKCS11_TEST_PIN` is set in `.vscode/.env`
- Verify YubiKey is plugged in: Run task "CLI: List available PKCS#11 tokens"
- Ensure libykcs11 is installed (Windows: comes with Yubico PIV Tool)

### "Can't debug tests"
- Ensure debugpy is installed: `pip install debugpy` (included in test deps)
- Check "Run and Debug" panel is open (`Ctrl+Shift+D`)
- Select a debug config from the dropdown and press `F5`

### "Tests pass in terminal but fail in VS Code"
- Your `.vscode/.env` might have different settings than your shell environment
- Open `.env` and verify `PKCS11_TEST_TOKEN` and `PKCS11_TEST_PIN` match

## Environment Variables Reference

Set these in `.vscode/.env` (or shell for command-line testing):

| Variable | Purpose | Example | Required |
|----------|---------|---------|----------|
| `PKCS11_TEST_TOKEN` | Token backend: 'yubikey' or 'softhsm' | `yubikey` | No (auto-detect) |
| `PKCS11_TEST_PIN` | User PIN for hardware token | `123456` | Yes if TOKEN=yubikey |
| `PKCS11_TEST_LABEL` | Token label (auto-detected) | `YubiKey PIV #123` | No |
| `SOFTHSM2_MODULE` | Path to libsofthsm2 (auto-detected) | `/usr/lib/softhsm/...` | No |

## Tips & Tricks

### Test Explorer Integration
- Left sidebar → "Testing" icon → Browse all tests visually
- Click a test to open its file
- Click the play icon to run that specific test
- Right-click for options (debug, run with coverage, etc.)

### Inline Coverage
- After running "Tests: Run with coverage", inline coverage appears in editor
- Green = covered line, red = uncovered line
- Hover over coverage gutters for statistics

### Quick Debugging
1. Add `import pdb; pdb.set_trace()` or `breakpoint()` in test code
2. Run test (terminal or debug config)
3. Debugger pauses at breakpoint; use VS Code debug panel to step through

### Keyboard Shortcuts
- `Ctrl+Shift+B` — Run default test task
- `Ctrl+Shift+D` — Open Run and Debug panel
- `F5` — Start debugging (if debug panel is open)
- `Ctrl+Shift+P` — Open Command Palette (to run tasks)

### Performance Tips
- Use "Tests: Run all (quick, no verbose)" for fast feedback loops
- Use "Tests: Run current file" to test only what you're editing
- Disable "autoTestDiscoverOnSaveEnabled" in settings.json if VS Code feels slow

## For More Information

- **Testing guide**: See `TESTING_WITH_HARDWARE.md` for detailed hardware/software token selection
- **Hardware setup**: See `README.md` in project root for YubiKey setup and provisioning
- **CLI tools**: Run `rnidstatus --help` for identity status and token discovery commands

---

**Last updated:** 2025-06-17 (Windows PKCS#11 backend and flexible test infrastructure)
