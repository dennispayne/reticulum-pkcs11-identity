"""
Tests for transparent RNS.Identity integration.
"""

import os
import sys
import pytest
import tempfile
from unittest.mock import Mock, patch

import reticulum_pkcs11_identity.rns_integration as rns_mod
from reticulum_pkcs11_identity.rns_integration import (
    _detect_app_name,
    _get_hardware_keys_for_app,
    enable_hardware_identity_injection,
    is_identity_hardware_backed,
    get_identity_app_name,
    get_identity_slot,
    _auto_initialize,
    _install_monkey_patch,
)


@pytest.fixture
def reset_patch_state():
    """Reset module-level patch globals around a test."""
    prev_installed = rns_mod._patch_installed
    prev_backend = rns_mod._auto_initialized_backend
    rns_mod._patch_installed = False
    rns_mod._auto_initialized_backend = None
    yield
    rns_mod._patch_installed = prev_installed
    rns_mod._auto_initialized_backend = prev_backend


@pytest.fixture
def fake_rns():
    """Install a fake RNS module with an Identity class into sys.modules."""
    import types

    rns = types.ModuleType("RNS")

    class Identity:
        def __init__(self, create_keys=True):
            self.pub_bytes = b"sw-x"
            self.sig_pub_bytes = b"sw-ed"

        def sign(self, message):
            return b"sw-sig:" + message

    rns.Identity = Identity
    rns.LOG_INFO = 4
    rns.log = Mock()

    prev = sys.modules.get("RNS")
    sys.modules["RNS"] = rns
    yield rns
    if prev is not None:
        sys.modules["RNS"] = prev
    else:
        del sys.modules["RNS"]


class TestAppDetection:
    """Test app name detection."""

    def test_detect_app_from_env_var(self):
        """Test app detection from environment variable."""
        os.environ["RNS_APP_NAME"] = "test_app"
        try:
            app_name = _detect_app_name()
            assert app_name == "test_app"
        finally:
            del os.environ["RNS_APP_NAME"]

    def test_detect_app_from_module_name(self):
        """Test app detection from calling module."""
        # This test just verifies the function doesn't crash
        app_name = _detect_app_name()
        # May be None or some module name - that's OK
        assert app_name is None or isinstance(app_name, str)


class TestHardwareKeyRetrieval:
    """Test hardware key retrieval for apps."""

    def test_get_hardware_keys_unknown_app(self):
        """Unknown app with no mapping and no backend returns None."""
        keys = _get_hardware_keys_for_app("unknown_app_xyz", backend=None)
        assert keys is None

    def test_get_hardware_keys_no_backend(self):
        """Key retrieval without backend returns None."""
        keys = _get_hardware_keys_for_app("any_app", backend=None)
        assert keys is None

    def test_get_hardware_keys_success(self):
        """Backend with a mapped slot returns (ed, x) public keys."""
        backend = Mock()
        backend.get_public_key_bytes.side_effect = [b"ed-pub", b"x-pub"]
        with patch.object(rns_mod, "AppIdentityMapper") as MapperCls:
            MapperCls.return_value.get_app_slot.return_value = "9a"
            keys = _get_hardware_keys_for_app("sideband", backend=backend)
        assert keys == (b"ed-pub", b"x-pub")

    def test_get_hardware_keys_no_slot(self):
        """When the app has no slot mapping, returns None."""
        backend = Mock()
        with patch.object(rns_mod, "AppIdentityMapper") as MapperCls:
            MapperCls.return_value.get_app_slot.return_value = None
            keys = _get_hardware_keys_for_app("sideband", backend=backend)
        assert keys is None

    def test_get_hardware_keys_backend_error_returns_none(self):
        """Backend errors are swallowed and return None."""
        backend = Mock()
        backend.get_public_key_bytes.side_effect = RuntimeError("token gone")
        with patch.object(rns_mod, "AppIdentityMapper") as MapperCls:
            MapperCls.return_value.get_app_slot.return_value = "9a"
            keys = _get_hardware_keys_for_app("sideband", backend=backend)
        assert keys is None


class TestIdentityIntrospection:
    """Test hardware identity detection."""

    def test_is_identity_hardware_backed_default(self):
        """Test identity is not hardware-backed by default."""
        class FakeIdentity:
            pass
        
        fake = FakeIdentity()
        assert not is_identity_hardware_backed(fake)

    def test_get_identity_app_name_none_by_default(self):
        """Test app name is None for non-hardware identity."""
        class FakeIdentity:
            pass
        
        fake = FakeIdentity()
        assert get_identity_app_name(fake) is None

    def test_get_identity_slot_none_by_default(self):
        """Test slot is None for non-hardware identity."""
        class FakeIdentity:
            pass
        
        fake = FakeIdentity()
        assert get_identity_slot(fake) is None


class TestMonkeyPatch:
    """Test monkey patching setup."""

    def test_enable_injection_without_rns(self):
        """Test that enabling injection without RNS doesn't crash."""
        # Hide RNS temporarily
        import sys
        rns_backup = sys.modules.get("RNS")
        if "RNS" in sys.modules:
            del sys.modules["RNS"]
        
        try:
            # Should not crash
            enable_hardware_identity_injection()
        finally:
            # Restore
            if rns_backup:
                sys.modules["RNS"] = rns_backup


class TestAutoInitialization:
    """Test auto-initialization at module import."""

    def test_auto_initialize_disabled_config(self):
        """Test auto-initialization with disabled config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config")
            
            # Create a config file with disabled hardware identity
            with open(config_path, "w") as f:
                f.write("[hardware_identity]\n")
                f.write("enabled = false\n")
            
            # Mock config loading
            with patch("reticulum_pkcs11_identity.rns_integration.load_hardware_identity_config") as mock_load_config:
                mock_load_config.return_value = {
                    "enabled": False,
                    "provider": None,
                    "token_label": None,
                    "exclude_apps": [],
                    "detected_providers": {}
                }
                
                # Call auto-init
                _auto_initialize()
                
                # Should have called config loading
                mock_load_config.assert_called_once()

    def test_auto_initialize_with_excluded_app(self):
        """Test auto-initialization skips excluded apps."""
        with patch("reticulum_pkcs11_identity.rns_integration.load_hardware_identity_config") as mock_load_config:
            with patch("reticulum_pkcs11_identity.rns_integration._detect_app_name") as mock_detect_app:
                mock_load_config.return_value = {
                    "enabled": True,
                    "provider": None,
                    "token_label": None,
                    "exclude_apps": ["myapp"],
                    "detected_providers": {}
                }
                mock_detect_app.return_value = "myapp"
                
                # Call auto-init
                _auto_initialize()
                
                # Should have loaded config and detected app
                mock_load_config.assert_called_once()
                mock_detect_app.assert_called_once()

    def test_auto_initialize_no_provider(self):
        """Test auto-initialization with no provider available."""
        with patch("reticulum_pkcs11_identity.rns_integration.load_hardware_identity_config") as mock_load_config:
            mock_load_config.return_value = {
                "enabled": True,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {}
            }
            
            # Call auto-init - should warn but not crash
            _auto_initialize()
            
            # Should have called config loading
            mock_load_config.assert_called_once()


class TestInstallMonkeyPatch:
    """Test _install_monkey_patch and patched RNS.Identity behavior."""

    def test_install_succeeds_and_is_idempotent(self, reset_patch_state, fake_rns):
        """Patch installs once, subsequent calls short-circuit to True."""
        backend = Mock()
        assert _install_monkey_patch(backend) is True
        assert rns_mod._patch_installed is True
        # Second call returns True without re-patching
        assert _install_monkey_patch(backend) is True

    def test_patched_init_adopts_hardware_identity(self, reset_patch_state, fake_rns):
        """When a token identity is available, the RNS identity adopts its public
        keys, hash and token-backed sign/decrypt — with no software private key."""
        backend = Mock()
        hw = Mock()
        hw.pub = "x-pub-obj"
        hw.pub_bytes = b"x-pub"
        hw.sig_pub = "ed-pub-obj"
        hw.sig_pub_bytes = b"ed-pub"
        hw.prv = object()  # truthy token-resident marker
        hw.sig_prv = "token-sign-adapter"
        hw.hash = b"hw-hash"
        hw.hexhash = "68772d68617368"
        hw._slot = "9a"
        hw.sign.return_value = b"hw-sig"
        with patch.object(rns_mod, "_detect_app_name", return_value="sideband"), \
             patch.object(rns_mod, "_build_hardware_identity_for_app", return_value=hw):
            assert _install_monkey_patch(backend) is True
            ident = fake_rns.Identity()

        assert ident.pub_bytes == b"x-pub"
        assert ident.sig_pub_bytes == b"ed-pub"
        assert ident.hash == b"hw-hash"
        # No software private key is retained.
        assert ident.prv_bytes is None
        assert ident.sig_prv_bytes is None
        assert is_identity_hardware_backed(ident) is True
        assert get_identity_app_name(ident) == "sideband"
        assert get_identity_slot(ident) == "9a"
        # sign() and decrypt() are routed to the token-backed identity.
        assert ident.sign(b"data") == b"hw-sig"
        assert ident.decrypt is hw.decrypt

    def test_patched_init_no_silent_software_fallback(self, reset_patch_state, fake_rns):
        """A token sign error propagates; it must NOT silently fall back to a
        software signature (which would not verify against the advertised key)."""
        backend = Mock()
        hw = Mock()
        hw.pub_bytes = b"x-pub"
        hw.sig_pub_bytes = b"ed-pub"
        hw.prv = object()
        hw.hash = b"hw-hash"
        hw.hexhash = "68772d68617368"
        hw._slot = "9a"
        hw.sign.side_effect = RuntimeError("token removed")
        with patch.object(rns_mod, "_detect_app_name", return_value="sideband"), \
             patch.object(rns_mod, "_build_hardware_identity_for_app", return_value=hw):
            _install_monkey_patch(backend)
            ident = fake_rns.Identity()

        with pytest.raises(RuntimeError):
            ident.sign(b"data")

    def test_patched_init_no_hardware_uses_software(self, reset_patch_state, fake_rns):
        """Without hardware keys, identity stays software-backed."""
        backend = Mock()
        with patch.object(rns_mod, "_detect_app_name", return_value=None), \
             patch.object(rns_mod, "_get_hardware_keys_for_app", return_value=None):
            _install_monkey_patch(backend)
            ident = fake_rns.Identity()

        assert ident.pub_bytes == b"sw-x"
        assert is_identity_hardware_backed(ident) is False


class TestEnableInjection:
    """Test enable_hardware_identity_injection."""

    def test_enable_with_explicit_backend(self, reset_patch_state, fake_rns):
        """Passing a backend installs the patch."""
        backend = Mock()
        enable_hardware_identity_injection(backend)
        assert rns_mod._patch_installed is True

    def test_enable_uses_auto_backend(self, reset_patch_state, fake_rns):
        """Falls back to the module-level auto-initialized backend."""
        rns_mod._auto_initialized_backend = Mock()
        enable_hardware_identity_injection()
        assert rns_mod._patch_installed is True

    def test_enable_no_backend_logs_via_rns(self, reset_patch_state, fake_rns):
        """No backend available -> informs via RNS.log, no patch."""
        enable_hardware_identity_injection(None)
        assert rns_mod._patch_installed is False
        fake_rns.log.assert_called_once()


class TestAutoInitializeProvider:
    """Test _auto_initialize provider branches."""

    def test_auto_initialize_installs_with_provider(self, reset_patch_state, fake_rns):
        """Configured provider -> backend created and patch installed."""
        with patch.object(rns_mod, "load_hardware_identity_config") as mock_cfg, \
             patch("reticulum_pkcs11_identity.backend.PKCS11Backend") as BackendCls:
            mock_cfg.return_value = {
                "enabled": True,
                "provider": "/usr/lib/softhsm.so",
                "token_label": "RNS-Test-Token",
                "exclude_apps": [],
                "detected_providers": {},
            }
            _auto_initialize()

        BackendCls.assert_called_once()
        assert rns_mod._patch_installed is True

    def test_auto_initialize_uses_auto_selected_provider(self, reset_patch_state, fake_rns):
        """Provider auto-selected from detected_providers when not explicit."""
        with patch.object(rns_mod, "load_hardware_identity_config") as mock_cfg, \
             patch("reticulum_pkcs11_identity.backend.PKCS11Backend") as BackendCls:
            mock_cfg.return_value = {
                "enabled": True,
                "provider": None,
                "token_label": None,
                "exclude_apps": [],
                "detected_providers": {"auto_selected": "/usr/lib/softhsm.so"},
            }
            _auto_initialize()

        BackendCls.assert_called_once()

    def test_auto_initialize_backend_error_swallowed(self, reset_patch_state, fake_rns):
        """Backend construction failure is handled gracefully."""
        with patch.object(rns_mod, "load_hardware_identity_config") as mock_cfg, \
             patch("reticulum_pkcs11_identity.backend.PKCS11Backend",
                   side_effect=RuntimeError("no token")):
            mock_cfg.return_value = {
                "enabled": True,
                "provider": "/usr/lib/softhsm.so",
                "token_label": "RNS-Test-Token",
                "exclude_apps": [],
                "detected_providers": {},
            }
            _auto_initialize()  # should not raise
        assert rns_mod._patch_installed is False

    def test_auto_initialize_config_error_swallowed(self, reset_patch_state):
        """Config loading failure is handled gracefully."""
        with patch.object(rns_mod, "load_hardware_identity_config",
                          side_effect=RuntimeError("bad config")):
            _auto_initialize()  # should not raise


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
