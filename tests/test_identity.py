"""
Comprehensive tests for Phase 3 identity and key provisioning.

Tests the factory functions:
  - make_lxmf_identity_class()
  - make_app_hardware_identity_class()
  - create_app_hardware_identity()
  - get_app_identity_keys()

And integration with RNS, session manager, and key provisioning.
"""

import os
import tempfile
import pytest

import RNS
from RNS.Cryptography import (
    Ed25519PublicKey,
    X25519PublicKey,
)

from reticulum_pkcs11_identity.identity import (
    make_lxmf_identity_class,
    make_hardware_identity_class,
    make_app_hardware_identity_class,
    create_app_hardware_identity,
    get_app_identity_keys,
)
from reticulum_pkcs11_identity.exceptions import (
    PKCS11BackendError,
    PKCS11KeyNotFoundError,
)
from reticulum_pkcs11_identity.app_identity import AppIdentityMapper


class TestMakeLXMFIdentityClass:
    """Test backward-compatible LXMF identity factory."""

    @pytest.mark.backend
    def test_make_lxmf_identity_class_creates_class(self, pkcs11_backend):
        """Test that make_lxmf_identity_class returns a class."""
        from conftest import SIGN_KEY_LABEL, ENC_KEY_LABEL

        cls = make_lxmf_identity_class(
            backend=pkcs11_backend,
            sign_key_label=SIGN_KEY_LABEL,
            enc_key_label=ENC_KEY_LABEL,
        )
        assert cls is not None
        assert hasattr(cls, "__name__")
        assert cls.__name__ == "LXMFIdentity"

    @pytest.mark.backend
    def test_make_lxmf_identity_class_instantiation(self, pkcs11_backend):
        """Test instantiating identity from LXMF factory."""
        from conftest import SIGN_KEY_LABEL, ENC_KEY_LABEL

        cls = make_lxmf_identity_class(
            backend=pkcs11_backend,
            sign_key_label=SIGN_KEY_LABEL,
            enc_key_label=ENC_KEY_LABEL,
        )
        identity = cls(create_keys=True)

        # Verify public keys are loaded
        assert identity.pub_bytes is not None
        assert identity.sig_pub_bytes is not None
        assert len(identity.pub_bytes) == 32
        assert len(identity.sig_pub_bytes) == 32

    @pytest.mark.backend
    def test_make_lxmf_identity_class_marks_as_hardware(self, pkcs11_backend):
        """Test that LXMF identity is marked as hardware-backed."""
        from conftest import SIGN_KEY_LABEL, ENC_KEY_LABEL

        cls = make_lxmf_identity_class(
            backend=pkcs11_backend,
            sign_key_label=SIGN_KEY_LABEL,
            enc_key_label=ENC_KEY_LABEL,
        )
        identity = cls(create_keys=True)
        assert identity._is_local_hardware is True

    @pytest.mark.backend
    def test_make_hardware_identity_class_alias(self, pkcs11_backend):
        """Test backward-compatible alias make_hardware_identity_class."""
        from conftest import SIGN_KEY_LABEL, ENC_KEY_LABEL

        cls = make_hardware_identity_class(
            backend=pkcs11_backend,
            sign_key_label=SIGN_KEY_LABEL,
            enc_key_label=ENC_KEY_LABEL,
        )
        identity = cls(create_keys=True)
        assert identity._is_local_hardware is True
        assert identity.pub_bytes is not None


class TestMakeAppHardwareIdentityClass:
    """Test multi-app hardware identity factory."""

    @pytest.mark.backend
    def test_make_app_hardware_identity_class_with_explicit_backend_and_slot(
        self, pkcs11_backend
    ):
        """Test creating app identity class with explicit backend and slot."""
        app_name = "test_app_factory"

        # First provision keys for the app
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name, slot="9a")
        assert ed_pub is not None
        assert x_pub is not None

        # Now create the identity class
        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )

        assert cls is not None
        assert hasattr(cls, "__name__")
        assert app_name in cls.__name__

    @pytest.mark.backend
    def test_make_app_hardware_identity_class_instantiation(self, pkcs11_backend):
        """Test instantiating identity from app factory."""
        app_name = "test_app_inst"

        # Provision keys
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        # Create class and instance
        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        identity = cls(create_keys=True)

        # Verify public keys match
        assert identity.pub_bytes == x_pub
        assert identity.sig_pub_bytes == ed_pub

    @pytest.mark.backend
    def test_make_app_hardware_identity_class_hash_computed(self, pkcs11_backend):
        """Test that app identity hash is correctly computed."""
        app_name = "test_app_hash"

        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        identity = cls(create_keys=True)

        # Hash should be computed
        assert identity.hash is not None
        assert identity.hexhash is not None
        assert len(identity.hash) == 20  # RNS uses 20-byte truncated hash

    @pytest.mark.backend
    def test_make_app_hardware_identity_class_repr(self, pkcs11_backend):
        """Test app identity repr includes app name and slot."""
        app_name = "test_app_repr"

        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9c",
        )
        identity = cls(create_keys=True)
        repr_str = repr(identity)

        assert app_name in repr_str
        assert "9c" in repr_str
        assert "hardware" in repr_str

    @pytest.mark.backend
    def test_make_app_hardware_identity_class_missing_keys_raises(
        self, pkcs11_backend
    ):
        """Test that missing keys raises error."""
        app_name = "app_with_no_keys_xyz"

        # Don't provision keys - should fail
        with pytest.raises(PKCS11KeyNotFoundError):
            cls = make_app_hardware_identity_class(
                app_name=app_name,
                backend=pkcs11_backend,
                slot="9a",
            )
            cls(create_keys=True)

    @pytest.mark.backend
    def test_make_app_hardware_identity_class_multiple_apps_different_keys(
        self, pkcs11_backend
    ):
        """Test that different apps have different keys."""
        app1 = "test_app_1_keys"
        app2 = "test_app_2_keys"

        # Provision keys for both apps
        ed1, x1 = pkcs11_backend.ensure_keys_for_app(app1)
        ed2, x2 = pkcs11_backend.ensure_keys_for_app(app2)

        assert ed1 != ed2
        assert x1 != x2

        # Create identities for both
        cls1 = make_app_hardware_identity_class(app1, pkcs11_backend, "9a")
        cls2 = make_app_hardware_identity_class(app2, pkcs11_backend, "9c")

        id1 = cls1(create_keys=True)
        id2 = cls2(create_keys=True)

        # Identities should have different hashes
        assert id1.hash != id2.hash


class TestCreateAppHardwareIdentity:
    """Test convenience function create_app_hardware_identity."""

    @pytest.mark.backend
    def test_create_app_hardware_identity_with_session(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test creating app identity with explicit backend."""
        from reticulum_pkcs11_identity.backend import PKCS11Backend
        from reticulum_pkcs11_identity.app_identity import AppIdentityMapper

        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        try:
            # Create backend and open session
            backend = PKCS11Backend(
                module_path=softhsm2_module_path,
                token_label="TestToken",
            )
            backend.open_session(pin="1234")
            
            try:
                # Allocate app
                mapper = AppIdentityMapper()
                app_name = "test_create_convenience"
                mapper.allocate_slot_for_app(app_name)

                # Ensure keys
                backend.ensure_keys_for_app(app_name)

                # Create identity
                identity = create_app_hardware_identity(app_name, backend=backend)
                assert identity is not None
                assert identity._is_local_hardware is True
                assert identity.pub_bytes is not None

            finally:
                backend.close()

        finally:
            if old_conf:
                os.environ["SOFTHSM2_CONF"] = old_conf
            elif "SOFTHSM2_CONF" in os.environ:
                del os.environ["SOFTHSM2_CONF"]

    def test_create_app_hardware_identity_no_session_returns_none(self):
        """Test that create_app_hardware_identity without backend returns None."""
        # Should return None gracefully when no backend provided
        identity = create_app_hardware_identity("unknown_app", backend=None)
        assert identity is None


class TestGetAppIdentityKeys:
    """Test get_app_identity_keys query function."""

    @pytest.mark.backend
    def test_get_app_identity_keys_returns_tuple(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test that get_app_identity_keys returns (ed_pub, x_pub) tuple."""
        from reticulum_pkcs11_identity.backend import PKCS11Backend
        from reticulum_pkcs11_identity.app_identity import AppIdentityMapper

        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        try:
            # Create backend and open session
            backend = PKCS11Backend(
                module_path=softhsm2_module_path,
                token_label="TestToken",
            )
            backend.open_session(pin="1234")
            
            try:
                # Allocate app
                mapper = AppIdentityMapper()
                app_name = "test_get_keys"
                mapper.allocate_slot_for_app(app_name)

                # Ensure keys
                ed_pub, x_pub = backend.ensure_keys_for_app(app_name)

                # Query keys
                keys = get_app_identity_keys(app_name, backend=backend)
                assert keys is not None
                assert len(keys) == 2
                assert keys[0] == ed_pub
                assert keys[1] == x_pub

            finally:
                backend.close()

        finally:
            if old_conf:
                os.environ["SOFTHSM2_CONF"] = old_conf
            elif "SOFTHSM2_CONF" in os.environ:
                del os.environ["SOFTHSM2_CONF"]

    @pytest.mark.backend
    def test_get_app_identity_keys_unknown_app_returns_none(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test that unknown app returns None."""
        from reticulum_pkcs11_identity.backend import PKCS11Backend

        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        try:
            # Create backend and open session
            backend = PKCS11Backend(
                module_path=softhsm2_module_path,
                token_label="TestToken",
            )
            backend.open_session(pin="1234")
            
            try:
                keys = get_app_identity_keys("unknown_app_xyz_no_mapping", backend=backend)
                assert keys is None

            finally:
                backend.close()

        finally:
            if old_conf:
                os.environ["SOFTHSM2_CONF"] = old_conf
            elif "SOFTHSM2_CONF" in os.environ:
                del os.environ["SOFTHSM2_CONF"]

    def test_get_app_identity_keys_no_session_returns_none(self):
        """Test that no backend returns None."""
        keys = get_app_identity_keys("any_app", backend=None)
        assert keys is None


class TestBackwardCompatibility:
    """Test backward compatibility between old and new factories."""

    @pytest.mark.backend
    def test_lxmf_identity_and_app_identity_same_structure(self, pkcs11_backend):
        """Test LXMF and app identities have same structure."""
        from conftest import SIGN_KEY_LABEL, ENC_KEY_LABEL

        # Create LXMF identity (old way)
        lxmf_cls = make_lxmf_identity_class(
            backend=pkcs11_backend,
            sign_key_label=SIGN_KEY_LABEL,
            enc_key_label=ENC_KEY_LABEL,
        )
        lxmf_identity = lxmf_cls(create_keys=True)

        # Create app identity (new way)
        app_name = "test_app_compat"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(
            app_name, SIGN_KEY_LABEL, ENC_KEY_LABEL
        )

        app_cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        app_identity = app_cls(create_keys=True)

        # Both should have same attributes
        assert hasattr(lxmf_identity, "pub_bytes")
        assert hasattr(app_identity, "pub_bytes")
        assert hasattr(lxmf_identity, "sig_pub_bytes")
        assert hasattr(app_identity, "sig_pub_bytes")
        assert hasattr(lxmf_identity, "_is_local_hardware")
        assert hasattr(app_identity, "_is_local_hardware")


class TestIdentitySigningAndDecryption:
    """Test signing and decryption operations on app identities."""

    @pytest.mark.backend
    def test_app_identity_signing(self, pkcs11_backend):
        """Test that app identity can sign messages."""
        app_name = "test_app_sign"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        identity = cls(create_keys=True)

        message = b"test message"
        signature = identity.sign(message)

        assert signature is not None
        assert len(signature) > 0

        # Verify signature using public key
        pub_key = Ed25519PublicKey.from_public_bytes(identity.sig_pub_bytes)
        pub_key.verify(signature, message)

    @pytest.mark.backend
    def test_app_identity_consistent_signatures(self, pkcs11_backend):
        """Test that same message produces same signature."""
        app_name = "test_app_consistent_sign"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        identity = cls(create_keys=True)

        message = b"consistent test"
        sig1 = identity.sign(message)
        sig2 = identity.sign(message)

        # Ed25519 should produce same signature for same input
        assert sig1 == sig2

    @pytest.mark.backend
    def test_app_identity_public_key_only_from_bytes(self, pkcs11_backend):
        """Test creating public-key-only identity from bytes."""
        app_name = "test_app_pubkey_only"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )

        # Create public-key-only identity
        pub_key_identity = cls.from_bytes(x_pub + ed_pub)
        assert pub_key_identity is not None
        assert pub_key_identity._is_local_hardware is False

    @pytest.mark.backend
    def test_app_identity_from_file_mismatch_warning(self, pkcs11_backend):
        """Test that from_file warns on mismatch with token."""
        app_name = "test_app_file_mismatch"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = os.path.join(tmpdir, "identity")

            # Write some mismatched data
            with open(identity_path, "wb") as f:
                f.write(b"x" * 64)

            # Load from file should warn but use token's identity
            identity = cls.from_file(identity_path)
            assert identity is not None
            assert identity.pub_bytes == x_pub


class TestIdentityKeyPersistence:
    """Test that keys persist and remain consistent."""

    @pytest.mark.backend
    def test_repeated_identity_creation_same_keys(self, pkcs11_backend):
        """Test that multiple identity creations return same public keys."""
        app_name = "test_app_persistence"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )

        # Create multiple identities
        id1 = cls(create_keys=True)
        id2 = cls(create_keys=True)

        # Keys should be identical
        assert id1.pub_bytes == id2.pub_bytes
        assert id1.sig_pub_bytes == id2.sig_pub_bytes
        assert id1.hash == id2.hash

    @pytest.mark.backend
    def test_identity_to_file_and_from_file(self, pkcs11_backend):
        """Test saving and loading identity from file."""
        app_name = "test_app_file_roundtrip"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        identity = cls(create_keys=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = os.path.join(tmpdir, "identity")

            # Save to file
            result = identity.to_file(identity_path)
            assert result is True
            assert os.path.isfile(identity_path)

            # Load from file
            loaded = cls.from_file(identity_path)
            assert loaded is not None
            assert loaded.hash == identity.hash
            assert loaded.pub_bytes == identity.pub_bytes


class TestIdentityErrorHandling:
    """Test error handling in identity operations."""

    @pytest.mark.backend
    def test_app_identity_signing_without_private_key_fails(self, pkcs11_backend):
        """Test that signing fails without private key."""
        app_name = "test_app_no_priv"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )

        # Create public-key-only identity
        pub_only = cls.from_bytes(x_pub + ed_pub)

        # Signing should fail
        with pytest.raises(KeyError):
            pub_only.sign(b"test")

    @pytest.mark.backend
    def test_app_identity_get_private_key_returns_public(self, pkcs11_backend):
        """Test that get_private_key returns public key for hardware identities."""
        app_name = "test_app_get_priv"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        identity = cls(create_keys=True)

        # For hardware identities, get_private_key returns public key
        priv_key = identity.get_private_key()
        assert priv_key == identity.get_public_key()


class TestMultipleAppsOnToken:
    """Test multiple applications sharing a single token."""

    @pytest.mark.backend
    def test_four_apps_on_four_slots(self, pkcs11_backend):
        """Test that four apps can be allocated on four PIV slots."""
        apps = ["app_slot_9a", "app_slot_9c", "app_slot_9d", "app_slot_9e"]
        slots = ["9a", "9c", "9d", "9e"]
        identities = []

        # Provision keys for all apps
        for app_name in apps:
            ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)
            assert ed_pub is not None
            assert x_pub is not None

        # Create identities for all apps
        for app_name, slot in zip(apps, slots):
            cls = make_app_hardware_identity_class(
                app_name=app_name,
                backend=pkcs11_backend,
                slot=slot,
            )
            identity = cls(create_keys=True)
            identities.append(identity)

        # Verify all identities are different
        hashes = [id.hash for id in identities]
        assert len(hashes) == len(set(hashes)), "All app hashes should be unique"

    @pytest.mark.backend
    def test_app_isolation_different_keys(self, pkcs11_backend):
        """Test that different apps have isolated, different keys."""
        app1 = "test_isolation_app1"
        app2 = "test_isolation_app2"

        ed1, x1 = pkcs11_backend.ensure_keys_for_app(app1)
        ed2, x2 = pkcs11_backend.ensure_keys_for_app(app2)

        # Keys must be different
        assert ed1 != ed2
        assert x1 != x2

        # Identities must be different
        cls1 = make_app_hardware_identity_class(app1, pkcs11_backend, "9a")
        cls2 = make_app_hardware_identity_class(app2, pkcs11_backend, "9c")

        id1 = cls1(create_keys=True)
        id2 = cls2(create_keys=True)

        assert id1.hash != id2.hash

    @pytest.mark.backend
    def test_app_label_verification(self, pkcs11_backend):
        """Test that app keys have correct labels."""
        app_name = "test_label_verify"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        # Verify labels
        sign_label = f"{app_name}-sign"
        enc_label = f"{app_name}-enc"

        # Retrieve by label should work
        ed_from_label = pkcs11_backend.get_public_key_bytes(key_label=sign_label)
        x_from_label = pkcs11_backend.get_public_key_bytes(key_label=enc_label)

        assert ed_pub == ed_from_label
        assert x_pub == x_from_label
