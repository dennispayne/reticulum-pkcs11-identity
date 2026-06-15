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
reticulum_pkcs11_identity
~~~~~~~~~~~~~~~~~~~~~~~~~

PKCS#11-backed identity support for Reticulum.

Import this package early in your application to enable hardware-token
identity support.  When ``identity_backend = pkcs11`` is present in your
Reticulum configuration the package automatically replaces ``RNS.Identity``
with a hardware-backed implementation.

Quick start::

    import reticulum_pkcs11_identity  # must come before any RNS usage
    import RNS

    reticulum = RNS.Reticulum()
    # RNS.Identity is now the hardware-backed class if configured.

See the README for full configuration instructions.
"""

from .backend import PKCS11Backend, SessionLifecycle
from .exceptions import (
    PKCS11BackendError,
    PKCS11ConfigError,
    PKCS11IdentityError,
    PKCS11KeyNotFoundError,
    PKCS11LoginError,
    PKCS11SessionError,
)
from .identity import make_hardware_identity_class
from .patch import apply_patch

__all__ = [
    "PKCS11Backend",
    "SessionLifecycle",
    "PKCS11BackendError",
    "PKCS11ConfigError",
    "PKCS11IdentityError",
    "PKCS11KeyNotFoundError",
    "PKCS11LoginError",
    "PKCS11SessionError",
    "make_hardware_identity_class",
    "apply_patch",
]

# Apply the patch automatically when the package is imported.
# This is a no-op if identity_backend is not "pkcs11" in the config.
apply_patch()
