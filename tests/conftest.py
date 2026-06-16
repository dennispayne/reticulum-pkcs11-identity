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

A fresh SoftHSM2 token is initialised once per test session.  Two key pairs
are generated on the token:

  lxmf-sign  — Ed25519 signing key
  lxmf-enc   — X25519 encryption key

All fixtures that require a PKCS#11 token will be skipped automatically if
SoftHSM2 is not installed.

Environment variables:
  SOFTHSM2_MODULE — path to libsofthsm2.so (auto-detected if not set)
  SOFTHSM2_CONF   — path to the softhsm2 configuration file (auto-created)
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
    An opened, logged-in PKCS#11 backend pointing at the test SoftHSM2 token.

    Key pairs are generated on the token if they do not already exist.
    The backend is closed at the end of the test session.
    """
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
