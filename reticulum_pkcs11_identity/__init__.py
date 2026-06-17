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

"""PKCS#11 support for explicit LXMF user identity provisioning."""

from .backend import PKCS11Backend, SessionLifecycle
from .config import load_hardware_identity_config
from .discovery import (
    discover_module_paths,
    enumerate_token_inventory,
    format_token_inventory,
    categorize_providers,
    select_provider,
)
from .exceptions import (
    PKCS11BackendError,
    PKCS11ConfigError,
    PKCS11IdentityError,
    PKCS11KeyNotFoundError,
    PKCS11LoginError,
    PKCS11SessionError,
)
from .identity import (
    make_hardware_identity_class,
    make_lxmf_identity_class,
    make_app_hardware_identity_class,
    create_app_hardware_identity,
    get_app_identity_keys,
)
from .lxmf import (
    LXMFHardwareIdentityConfig,
    LXMFHardwareIdentityHandle,
    create_lxmf_hardware_identity,
    load_lxmf_hardware_identity_config,
)

__all__ = [
    "PKCS11Backend",
    "SessionLifecycle",
    "PKCS11BackendError",
    "PKCS11ConfigError",
    "PKCS11IdentityError",
    "PKCS11KeyNotFoundError",
    "PKCS11LoginError",
    "PKCS11SessionError",
    "load_hardware_identity_config",
    "make_lxmf_identity_class",
    "make_hardware_identity_class",
    "make_app_hardware_identity_class",
    "create_app_hardware_identity",
    "get_app_identity_keys",
    "LXMFHardwareIdentityConfig",
    "LXMFHardwareIdentityHandle",
    "load_lxmf_hardware_identity_config",
    "create_lxmf_hardware_identity",
    "discover_module_paths",
    "enumerate_token_inventory",
    "format_token_inventory",
    "categorize_providers",
    "select_provider",
]
