"""Tests for the experimental subpackage: gate + API sectioning."""

import pytest

import reticulum_pkcs11_identity as rpi
from reticulum_pkcs11_identity import experimental
from reticulum_pkcs11_identity.exceptions import PKCS11ExperimentalDisabledError


def test_experimental_api_is_importable():
    """The multi-identity API is reachable via the experimental namespace."""
    for name in (
        "AppIdentityMapper",
        "get_or_create_hardware_identity",
        "TransparentHardwareIdentityFactory",
        "make_app_hardware_identity_class",
        "create_app_hardware_identity",
        "get_app_identity_keys",
    ):
        assert hasattr(experimental, name), name


def test_multi_app_factories_not_on_production_top_level():
    """Sectioned off: the multi-identity factories are not top-level API."""
    for name in (
        "make_app_hardware_identity_class",
        "create_app_hardware_identity",
        "get_app_identity_keys",
    ):
        assert not hasattr(rpi, name), f"{name} should only live under .experimental"


def test_require_multi_identity_raises_when_disabled():
    with pytest.raises(PKCS11ExperimentalDisabledError):
        experimental.require_multi_identity(
            {"experimental_features": False, "multi_identity": False}
        )


def test_require_multi_identity_passes_when_enabled():
    # Should not raise when both flags are on.
    experimental.require_multi_identity(
        {"experimental_features": True, "multi_identity": True}
    )
