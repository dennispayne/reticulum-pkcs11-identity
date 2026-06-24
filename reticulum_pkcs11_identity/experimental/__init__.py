"""Experimental, opt-in features for ``reticulum_pkcs11_identity``.

Everything here is gated behind config and kept separate from the production
surface to reduce clutter. The production model is intentionally simple: **one**
hardware identity (an Ed25519 sign key + an X25519 enc key) used across many
apps, with RNS *aspects* providing per-app addresses for free.

This subpackage holds the alternative **multi-identity / per-app-slot** model:
each app gets its own keypair in its own PIV slot. That buys *unlinkability*
(separate public keys per app) at the cost of complexity and slots -- a
deliberate "personas" choice, not something needed for ordinary multi-app use.

Enabling
--------
Add to the ``[hardware_identity]`` section of your Reticulum config::

    [hardware_identity]
    experimental_features = on
    multi_identity = on

Both flags are required. Until then:
  * the transparent injection / ``get_or_create_hardware_identity`` path stays
    inert (apps fall back to a normal software/single identity), and
  * the CLI hides the per-app slot view.

The explicit API below is always importable (importing from this subpackage is
itself the opt-in); call :func:`require_multi_identity` first if you want a hard
config check.
"""

from ..config import multi_identity_enabled
from ..exceptions import PKCS11ExperimentalDisabledError
from .app_identity import AppIdentityMapper, PIV_SLOTS, PIV_SLOT_NAMES
from .transparent_identity import (
    TransparentHardwareIdentityFactory,
    get_or_create_hardware_identity,
    is_app_using_hardware,
    get_app_hardware_slot,
    list_all_app_slots,
)
# Multi-app identity factories live in the core identity module (they are
# tightly coupled to its internals); they are surfaced here so the whole
# experimental API is discoverable from one place.
from ..identity import (
    make_app_hardware_identity_class,
    create_app_hardware_identity,
    get_app_identity_keys,
)


def require_multi_identity(config=None) -> None:
    """Raise :class:`PKCS11ExperimentalDisabledError` unless multi-identity is on.

    Use at the top of an explicit multi-identity entry point when you want a
    hard config gate rather than the soft "return None / fall back" behaviour.
    """
    if not multi_identity_enabled(config):
        raise PKCS11ExperimentalDisabledError(
            "The multi-identity feature is experimental and disabled. Enable it "
            "by setting `experimental_features = on` and `multi_identity = on` in "
            "the [hardware_identity] section of your Reticulum config."
        )


__all__ = [
    "multi_identity_enabled",
    "require_multi_identity",
    "PKCS11ExperimentalDisabledError",
    "AppIdentityMapper",
    "PIV_SLOTS",
    "PIV_SLOT_NAMES",
    "TransparentHardwareIdentityFactory",
    "get_or_create_hardware_identity",
    "is_app_using_hardware",
    "get_app_hardware_slot",
    "list_all_app_slots",
    "make_app_hardware_identity_class",
    "create_app_hardware_identity",
    "get_app_identity_keys",
]
