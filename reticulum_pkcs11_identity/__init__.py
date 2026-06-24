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

"""PKCS#11 hardware-backed identities for Reticulum."""

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
)
# The multi-identity API (per-app factories + slot mapper + transparent
# injection) is experimental and gated by config; it lives under
# ``reticulum_pkcs11_identity.experimental`` to keep the production surface lean.
from . import experimental
from .hardware_identity import (
    HardwareIdentityConfig,
    HardwareIdentityHandle,
    create_hardware_identity,
    load_hardware_identity_binding,
)
from .rns_integration import (
    enable_hardware_identity_injection,
    is_identity_hardware_backed,
    get_identity_app_name,
    get_identity_slot,
)
from .session_bootstrap import (
    BootstrapOutcome,
    BootstrapResult,
    TokenClassification,
    TokenStatus,
    bootstrap_session,
    classify_token,
    provision_identity_via_ykman,
    run_interactive_bootstrap,
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
    "make_hardware_identity_class",
    "experimental",
    "HardwareIdentityConfig",
    "HardwareIdentityHandle",
    "load_hardware_identity_binding",
    "create_hardware_identity",
    "discover_module_paths",
    "enumerate_token_inventory",
    "format_token_inventory",
    "categorize_providers",
    "select_provider",
    "enable_hardware_identity_injection",
    "is_identity_hardware_backed",
    "get_identity_app_name",
    "get_identity_slot",
    "classify_token",
    "bootstrap_session",
    "run_interactive_bootstrap",
    "provision_identity_via_ykman",
    "TokenStatus",
    "TokenClassification",
    "BootstrapOutcome",
    "BootstrapResult",
]
