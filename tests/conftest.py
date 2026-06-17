# Reticulum PKCS#11 Identity - License
#
# Copyright (c) 2024 Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
pytest fixtures for the reticulum_pkcs11_identity test suite.

Token selection:
  PKCS11_TEST_TOKEN environment variable controls which token to use:
    'hw'       — Use real hardware (YubiKey). Requires PKCS11_TEST_PIN
    'softhsm'  — Use SoftHSM2 (default if not set or SoftHSM2 unavailable)
  
  Example: PKCS11_TEST_TOKEN=hw PKCS11_TEST_PIN=123456 pytest tests/

A fresh SoftHSM2 token is initialised once per test session.  Two key pairs
are generated on the token:

  lxmf-sign  — Ed25519 signing key
  lxmf-enc   — X25519 encryption key

All fixtures that require a PKCS#11 token will be skipped automatically if
the selected token backend is not available.

Environment variables:
  SOFTHSM2_MODULE       — path to libsofthsm2.so (auto-detected if not set)
  SOFTHSM2_CONF         — path to the softhsm2 configuration file (auto-created)
  PKCS11_TEST_TOKEN     — 'hw' for hardware or 'softhsm' for SoftHSM2 (default: auto-detect)
  PKCS11_TEST_PIN       — PIN for hardware token (user PIN, required if PKCS11_TEST_TOKEN=hw)
  PKCS11_TEST_LABEL     — Token label for hardware token (auto-detected if not set)
"""

import os
import shutil
import subprocess
import tempfile

import pytest

# ----- Paths and constants ------------------------------------------------

_DEFAULT_MODULE_CANDIDATES = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
]

TOKEN_LABEL = "RNS-Test-Token"
TOKEN_PIN   = "1234"
TOKEN_SOPIN = "12345678"
SIGN_KEY_LABEL = "lxmf-sign"
ENC_KEY_LABEL  = "lxmf-enc"


def _find_softhsm_module() -> str | None:
    module = os.environ.get("SOFTHSM2_MODULE")
    if module and os.path.isfile(module):
        return module
    for path in _DEFAULT_MODULE_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def _find_hardware_token_provider() -> tuple[str, str] | None:
    """
    Find a hardware PKCS#11 provider (e.g., libykcs11.dll on Windows).
    
    Returns:
        (provider_path, token_label) if found, None otherwise
    """
    # Try YubiKey on Windows
    candidates = [
        r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
        r"C:\Program Files (x86)\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
        # Linux/macOS
        "/usr/lib/x86_64-linux-gnu/libykcs11.so",
        "/usr/lib/libykcs11.so",
        "/usr/local/lib/libykcs11.so",
    ]
    
    for provider_path in candidates:
        if os.path.exists(provider_path):
            # Try to discover token label from environment or auto-detect
            token_label = os.environ.get("PKCS11_TEST_LABEL")
            if not token_label:
                # For YubiKey, use default PIV label
                token_label = "YubiKey PIV"
            return (provider_path, token_label)
    
    return None


def _get_test_token_backend() -> str:
    """
    Determine which token backend to use for tests.
    
    Returns:
        'hw' if hardware token should be used
        'softhsm' if SoftHSM2 should be used
        Raises pytest.skip() if neither is available
    """
    requested = os.environ.get("PKCS11_TEST_TOKEN", "").lower()
    
    if requested == "hw":
        # User explicitly requested hardware token
        if not os.environ.get("PKCS11_TEST_PIN"):
            pytest.skip(
                "PKCS11_TEST_TOKEN=hw but PKCS11_TEST_PIN not set. "
                "Set PKCS11_TEST_PIN=<pin> to use hardware token."
            )
        if _find_hardware_token_provider() is None:
            pytest.skip(
                "PKCS11_TEST_TOKEN=hw but no hardware PKCS#11 provider found. "
                "Ensure YubiKey is plugged in and libykcs11 is installed."
            )
        return "hw"
    
    if requested == "softhsm":
        # User explicitly requested SoftHSM2
        if _find_softhsm_module() is None:
            pytest.skip("PKCS11_TEST_TOKEN=softhsm but SoftHSM2 is not installed")
        return "softhsm"
    
    # Auto-detect: prefer SoftHSM2 for safety, fall back to hw if available
    if _find_softhsm_module() is not None:
        return "softhsm"
    
    # If SoftHSM2 not available but hardware PIN is set, use hardware
    if os.environ.get("PKCS11_TEST_PIN") and _find_hardware_token_provider() is not None:
        return "hw"
    
    pytest.skip(
        "No PKCS#11 token available. Either install SoftHSM2 or set "
        "PKCS11_TEST_TOKEN=hw with PKCS11_TEST_PIN=<pin> for hardware token."
    )


def _softhsm2_util(*args, env=None) -> subprocess.CompletedProcess:
    cmd = ["softhsm2-util"] + list(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


# ----- Session-scoped token fixture ----------------------------------------


@pytest.fixture(scope="session")
def softhsm2_module_path():
    """Path to libsofthsm2.so, or skip the test if SoftHSM2 is not installed."""
    if shutil.which("softhsm2-util") is None:
        pytest.skip(
            "SoftHSM2 is not installed (missing softhsm2-util); run scripts/install_test_deps.sh "
            "or install SoftHSM2 manually to run PKCS#11 tests"
        )

    path = _find_softhsm_module()
    if path is None:
        pytest.skip(
            "SoftHSM2 is not installed (missing libsofthsm2.so); run scripts/install_test_deps.sh "
            "or install SoftHSM2 manually to run PKCS#11 tests"
        )
    return path


@pytest.fixture(scope="session")
def softhsm2_env(tmp_path_factory):
    """
    Initialise a temporary SoftHSM2 token for the entire test session.

    Yields a dict of environment variables that point softhsm2-util and
    python-pkcs11 at the temporary token directory.
    """
    token_dir = tmp_path_factory.mktemp("softhsm2_tokens")
    conf_path = str(token_dir.parent / "softhsm2.conf")

    # Write a minimal softhsm2 config that points at our temp token directory.
    with open(conf_path, "w") as fh:
        fh.write(f"directories.tokendir = {token_dir}\n")
        fh.write("objectstore.backend = file\n")
        fh.write("log.level = ERROR\n")
        fh.write("slots.removable = false\n")

    env = dict(os.environ)
    env["SOFTHSM2_CONF"] = conf_path

    # Initialise the token.
    result = _softhsm2_util(
        "--init-token",
        "--slot", "0",
        "--label", TOKEN_LABEL,
        "--pin", TOKEN_PIN,
        "--so-pin", TOKEN_SOPIN,
        env=env,
    )
    assert result.returncode == 0, (
        f"softhsm2-util --init-token failed:\n{result.stdout}\n{result.stderr}"
    )

    yield env


@pytest.fixture(scope="session")
def pkcs11_backend(softhsm2_module_path, softhsm2_env):
    """
    An opened, logged-in PKCS#11 backend pointing at the test token.

    Token selection is determined by PKCS11_TEST_TOKEN environment variable:
      - 'hw': Use real hardware (YubiKey) - requires PKCS11_TEST_PIN
      - 'softhsm': Use SoftHSM2 (default)
      - Not set: Auto-detect (prefer SoftHSM2)

    Key pairs are generated on the token if they do not already exist.
    The backend is closed at the end of the test session.
    """
    backend_type = _get_test_token_backend()
    
    if backend_type == "hw":
        # Use hardware token
        from reticulum_pkcs11_identity.backend import PKCS11Backend
        
        provider_info = _find_hardware_token_provider()
        if provider_info is None:
            pytest.skip("Hardware token provider not found")
        
        provider_path, token_label = provider_info
        pin = os.environ.get("PKCS11_TEST_PIN")
        
        backend = PKCS11Backend(
            module_path=provider_path,
            token_label=token_label,
        )
        backend.open_session(pin=pin)
        
        # For hardware token, keys should already exist or be skipped
        # (YubiKey doesn't support arbitrary key generation)
        
        yield backend
        backend.close()
    
    else:
        # Use SoftHSM2 (default)
        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        from reticulum_pkcs11_identity.backend import PKCS11Backend

        backend = PKCS11Backend(
            module_path=softhsm2_module_path,
            token_label=TOKEN_LABEL,
        )
        backend.open_session(pin=TOKEN_PIN)

        # Generate test key pairs (idempotent — skip if already present).
        from reticulum_pkcs11_identity.exceptions import PKCS11KeyNotFoundError
        try:
            backend.get_public_key_bytes(key_label=SIGN_KEY_LABEL)
        except PKCS11KeyNotFoundError:
            backend.generate_ed25519_keypair(label=SIGN_KEY_LABEL)

        try:
            backend.get_public_key_bytes(key_label=ENC_KEY_LABEL)
        except PKCS11KeyNotFoundError:
            backend.generate_x25519_keypair(label=ENC_KEY_LABEL)

        yield backend

        backend.close()
        if old_conf is not None:
            os.environ["SOFTHSM2_CONF"] = old_conf
        elif "SOFTHSM2_CONF" in os.environ:
            del os.environ["SOFTHSM2_CONF"]



@pytest.fixture(scope="session")
def hardware_identity_class(pkcs11_backend):
    """The HardwareIdentity class bound to the test token."""
    from reticulum_pkcs11_identity.identity import make_hardware_identity_class
    return make_hardware_identity_class(
        backend=pkcs11_backend,
        sign_key_label=SIGN_KEY_LABEL,
        enc_key_label=ENC_KEY_LABEL,
    )


@pytest.fixture(scope="session")
def hardware_identity(hardware_identity_class):
    """A single HardwareIdentity instance for the test session."""
    return hardware_identity_class(create_keys=True)


# ----- pytest hooks for early initialization --------------------------------


def pytest_configure(config):
    """
    Initialize SoftHSM2 early during test discovery.
    
    This hook runs before any tests are collected, ensuring SOFTHSM2_CONF
    is set in the environment. This prevents discovery failures in VS Code
    and other IDEs.
    """
    # Only initialize once, even if this hook is called multiple times
    if "SOFTHSM2_CONF" in os.environ:
        return
    
    # Only auto-initialize if we're using SoftHSM2 (not explicitly using hardware)
    if os.environ.get("PKCS11_TEST_TOKEN", "").lower() == "hw":
        return
    
    # Check if SoftHSM2 is available
    if shutil.which("softhsm2-util") is None:
        # SoftHSM2 not installed, but tests may skip gracefully
        return
    
    module_path = _find_softhsm_module()
    if module_path is None:
        return
    
    # Create a temporary directory for SoftHSM2 token
    token_dir = tempfile.mkdtemp(prefix="softhsm2_tokens_")
    conf_path = os.path.join(os.path.dirname(token_dir), "softhsm2.conf")
    
    # Write SoftHSM2 config
    with open(conf_path, "w") as fh:
        fh.write(f"directories.tokendir = {token_dir}\n")
        fh.write("objectstore.backend = file\n")
        fh.write("log.level = ERROR\n")
        fh.write("slots.removable = false\n")
    
    # Set environment variable
    os.environ["SOFTHSM2_CONF"] = conf_path
    
    # Initialize the token
    env = dict(os.environ)
    result = _softhsm2_util(
        "--init-token",
        "--slot", "0",
        "--label", TOKEN_LABEL,
        "--pin", TOKEN_PIN,
        "--so-pin", TOKEN_SOPIN,
        env=env,
    )
    
    if result.returncode != 0:
        # If initialization fails, unset the config so tests skip gracefully
        if "SOFTHSM2_CONF" in os.environ:
            del os.environ["SOFTHSM2_CONF"]

