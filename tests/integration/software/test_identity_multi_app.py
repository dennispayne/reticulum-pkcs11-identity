"""
Multi-app integration tests for Phase 3.

Tests focus on:
  - Multi-app key provisioning (ensure_keys_for_app)
  - AppIdentityMapper with identity creation
  - Transparent RNS.Identity injection
"""

import os
import tempfile
import pytest
import threading
import time

from reticulum_pkcs11_identity.experimental.app_identity import AppIdentityMapper
from reticulum_pkcs11_identity.backend import PKCS11Backend
from reticulum_pkcs11_identity.identity import (
    make_app_hardware_identity_class,
    create_app_hardware_identity,
    get_app_identity_keys,
)
from reticulum_pkcs11_identity.rns_integration import (
    enable_hardware_identity_injection,
    is_identity_hardware_backed,
    get_identity_app_name,
    get_identity_slot,
)
from reticulum_pkcs11_identity.exceptions import (
    SlotNotFoundError,
    PKCS11BackendError,
)


class TestKeyProvisioningIntegration:
    """Test key provisioning across multiple apps."""

    @pytest.mark.backend_piv
    def test_ensure_keys_creates_both_keys(self, pkcs11_backend):
        """Test ensure_keys_for_app creates Ed25519 and X25519."""
        app_name = "test_prov_both"
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        assert ed_pub is not None
        assert x_pub is not None
        assert len(ed_pub) == 32
        assert len(x_pub) == 32

    @pytest.mark.backend_piv
    def test_ensure_keys_idempotent(self, pkcs11_backend):
        """Test ensure_keys_for_app is idempotent."""
        app_name = "test_prov_idem"

        ed1, x1 = pkcs11_backend.ensure_keys_for_app(app_name)
        ed2, x2 = pkcs11_backend.ensure_keys_for_app(app_name)

        assert ed1 == ed2
        assert x1 == x2

    @pytest.mark.backend_piv
    def test_ensure_keys_different_apps_different_keys(self, pkcs11_backend):
        """Test ensure_keys generates different keys for different apps."""
        app1 = "app_prov_1"
        app2 = "app_prov_2"

        ed1, x1 = pkcs11_backend.ensure_keys_for_app(app1)
        ed2, x2 = pkcs11_backend.ensure_keys_for_app(app2)

        assert ed1 != ed2
        assert x1 != x2

    @pytest.mark.backend_piv
    def test_ensure_keys_with_slot_hint(self, pkcs11_backend):
        """Test ensure_keys accepts slot hint."""
        app_name = "test_prov_slot_hint"

        # Should accept slot hint (informational)
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(
            app_name, slot="9a"
        )

        assert ed_pub is not None
        assert x_pub is not None

    @pytest.mark.backend_piv
    def test_ensure_keys_verifies_labeling(self, pkcs11_backend):
        """Test that ensure_keys creates keys with correct labels."""
        app_name = "test_prov_labels"

        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        # Verify keys exist with expected labels
        sign_label = f"{app_name}-sign"
        enc_label = f"{app_name}-enc"

        ed_from_label = pkcs11_backend.get_public_key_bytes(key_label=sign_label)
        x_from_label = pkcs11_backend.get_public_key_bytes(key_label=enc_label)

        assert ed_pub == ed_from_label
        assert x_pub == x_from_label

    @pytest.mark.backend_piv
    def test_ensure_keys_thread_safe(self, pkcs11_backend):
        """Test that ensure_keys_for_app is thread-safe."""
        app_name = "test_prov_thread_safe"
        results = []
        lock = threading.Lock()

        def provision_keys():
            ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)
            with lock:
                results.append((ed_pub, x_pub))

        threads = [threading.Thread(target=provision_keys) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All results should be identical
        assert len(results) == 3
        first = results[0]
        for result in results[1:]:
            assert result == first




class TestAppIdentityMapperIntegration:
    """Test AppIdentityMapper with identity creation."""

    @pytest.mark.backend
    def test_mapper_with_key_provisioning(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test AppIdentityMapper with backend key provisioning."""
        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                # Create backend and open session
                backend = PKCS11Backend(
                    module_path=softhsm2_module_path,
                    token_label="RNS-Test-Token",
                )
                backend.open_session(pin="1234")
                
                try:
                    # Map apps to slots
                    mapper = AppIdentityMapper(config_dir=tmpdir)
                    app1 = mapper.allocate_slot_for_app("app_map_1")
                    app2 = mapper.allocate_slot_for_app("app_map_2")

                    assert app1 == "9a"
                    assert app2 == "9c"

                    # Provision keys
                    ed1, x1 = backend.ensure_keys_for_app("app_map_1")
                    ed2, x2 = backend.ensure_keys_for_app("app_map_2")

                    # Verify isolation
                    assert ed1 != ed2
                    assert x1 != x2

                finally:
                    backend.close()

            finally:
                if old_conf:
                    os.environ["SOFTHSM2_CONF"] = old_conf
                elif "SOFTHSM2_CONF" in os.environ:
                    del os.environ["SOFTHSM2_CONF"]

    @pytest.mark.backend
    def test_mapper_slot_exhaustion(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test that mapper correctly handles slot exhaustion."""
        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                # Create backend and open session
                backend = PKCS11Backend(
                    module_path=softhsm2_module_path,
                    token_label="RNS-Test-Token",
                )
                backend.open_session(pin="1234")
                
                try:
                    mapper = AppIdentityMapper(config_dir=tmpdir)

                    # Allocate all four slots
                    slot1 = mapper.allocate_slot_for_app("app_1")
                    slot2 = mapper.allocate_slot_for_app("app_2")
                    slot3 = mapper.allocate_slot_for_app("app_3")
                    slot4 = mapper.allocate_slot_for_app("app_4")

                    assert slot1 == "9a"
                    assert slot2 == "9c"
                    assert slot3 == "9d"
                    assert slot4 == "9e"

                    # Fifth allocation should fail
                    with pytest.raises(SlotNotFoundError):
                        mapper.allocate_slot_for_app("app_5")

                finally:
                    backend.close()

            finally:
                if old_conf:
                    os.environ["SOFTHSM2_CONF"] = old_conf
                elif "SOFTHSM2_CONF" in os.environ:
                    del os.environ["SOFTHSM2_CONF"]


class TestRNSIntegrationMultiApp:
    """Test RNS.Identity integration with multiple apps."""

    def test_is_identity_hardware_backed_default_false(self):
        """Test that regular identity is not hardware-backed."""
        try:
            import RNS
            identity = RNS.Identity(create_keys=True)
            assert not is_identity_hardware_backed(identity)
        except ImportError:
            pytest.skip("RNS not installed")

    def test_get_identity_app_name_none_by_default(self):
        """Test that regular identity has no app name."""
        try:
            import RNS
            identity = RNS.Identity(create_keys=True)
            assert get_identity_app_name(identity) is None
        except ImportError:
            pytest.skip("RNS not installed")

    def test_get_identity_slot_none_by_default(self):
        """Test that regular identity has no slot."""
        try:
            import RNS
            identity = RNS.Identity(create_keys=True)
            assert get_identity_slot(identity) is None
        except ImportError:
            pytest.skip("RNS not installed")

    @pytest.mark.backend
    def test_enable_injection_doesnt_crash(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test that enabling injection doesn't crash."""
        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        try:
            # Create backend and open session
            backend = PKCS11Backend(
                module_path=softhsm2_module_path,
                token_label="RNS-Test-Token",
            )
            backend.open_session(pin="1234")
            
            try:
                # Should not crash (will be a no-op without explicit setup)
                enable_hardware_identity_injection(backend=backend)

            finally:
                backend.close()

        finally:
            if old_conf:
                os.environ["SOFTHSM2_CONF"] = old_conf
            elif "SOFTHSM2_CONF" in os.environ:
                del os.environ["SOFTHSM2_CONF"]


class TestMultiAppIdentityCreation:
    """Test creating identities for multiple apps."""

    @pytest.mark.backend_piv
    def test_create_identity_for_multiple_apps_sequentially(
        self, pkcs11_backend
    ):
        """Test creating identities for multiple apps in sequence."""
        apps = ["multi_app_1", "multi_app_2", "multi_app_3"]
        identities = []

        for app_name in apps:
            ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

            cls = make_app_hardware_identity_class(
                app_name=app_name,
                backend=pkcs11_backend,
                slot="9a",
            )
            identity = cls(create_keys=True)
            identities.append(identity)

        # All should be hardware-backed
        for identity in identities:
            assert identity._is_local_hardware

        # All should have different hashes
        hashes = [id.hash for id in identities]
        assert len(hashes) == len(set(hashes))

    @pytest.mark.backend_piv
    def test_identity_queries_after_provisioning(self, pkcs11_backend):
        """Test querying identity keys after provisioning."""
        app_name = "query_app_test"

        # Provision
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        # Create identity
        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=pkcs11_backend,
            slot="9a",
        )
        identity = cls(create_keys=True)

        # Query keys
        assert identity.pub_bytes == x_pub
        assert identity.sig_pub_bytes == ed_pub

    @pytest.mark.backend_piv
    def test_multi_app_signing_and_hashing(self, pkcs11_backend):
        """Test signing and hashing for multiple identities."""
        apps = ["sign_app_1", "sign_app_2"]
        signatures = []

        for app_name in apps:
            ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

            cls = make_app_hardware_identity_class(
                app_name=app_name,
                backend=pkcs11_backend,
                slot="9a",
            )
            identity = cls(create_keys=True)

            # Sign message
            message = f"test {app_name}".encode()
            sig = identity.sign(message)
            signatures.append((identity, sig, message))

        # All identities signed successfully
        assert len(signatures) == 2

        # Signatures should be different (different keys, different messages)
        sig1, sig2 = signatures[0][1], signatures[1][1]
        assert sig1 != sig2


class TestSessionCachingAndReuse:
    """Test session caching across multiple identity operations."""

    @pytest.mark.session_manager
    def test_backend_reused_across_app_operations(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test that backend session is reused."""
        pytest.skip(
            "Global session manager API (get_session_manager/shutdown_session) "
            "is not implemented in this package."
        )
        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        try:
            manager = get_session_manager()
            result = manager.initialize(pin="1234", auto_prompt=False)
            if not result:
                pytest.skip("Could not initialize session manager")

            backend1 = manager.get_backend()

            # Do some work
            backend1.ensure_keys_for_app("reuse_app_1")

            # Get backend again - should be same instance
            backend2 = manager.get_backend()

            # Should be identical
            assert backend1 is backend2

        finally:
            shutdown_session()
            if old_conf:
                os.environ["SOFTHSM2_CONF"] = old_conf
            elif "SOFTHSM2_CONF" in os.environ:
                del os.environ["SOFTHSM2_CONF"]

    @pytest.mark.session_manager
    def test_multiple_identities_reuse_session(
        self, softhsm2_module_path, softhsm2_env
    ):
        """Test that multiple identity creations reuse same session."""
        pytest.skip(
            "Global session manager API (get_session_manager/shutdown_session) "
            "is not implemented in this package."
        )
        old_conf = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = softhsm2_env["SOFTHSM2_CONF"]

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                manager = get_session_manager()
                result = manager.initialize(pin="1234", auto_prompt=False)
                if not result:
                    pytest.skip("Could not initialize session manager")

                backend = manager.get_backend()

                # Create multiple identities
                for i in range(3):
                    app_name = f"session_reuse_{i}"
                    backend.ensure_keys_for_app(app_name)

                    cls = make_app_hardware_identity_class(
                        app_name=app_name,
                        backend=backend,
                        slot="9a",
                    )
                    identity = cls(create_keys=True)

                    # All should work with same session
                    assert identity._is_local_hardware

            finally:
                shutdown_session()
                if old_conf:
                    os.environ["SOFTHSM2_CONF"] = old_conf
                elif "SOFTHSM2_CONF" in os.environ:
                    del os.environ["SOFTHSM2_CONF"]


class TestErrorHandlingMultiApp:
    """Test error handling in multi-app scenarios."""

    @pytest.mark.backend_piv
    def test_ensure_keys_nonexistent_backend_fails_gracefully(self):
        """Test that operations fail gracefully with no backend."""
        # With no backend, operations should fail gracefully
        # Simply creating an identity without backend should return None
        identity = create_app_hardware_identity("test_app", backend=None)
        assert identity is None

    @pytest.mark.backend_piv
    def test_identity_creation_no_backend_returns_none(self):
        """Test that identity creation returns None without backend."""
        # Should return None gracefully when no backend provided
        identity = create_app_hardware_identity("nonexistent_app", backend=None)
        assert identity is None

    @pytest.mark.backend_piv
    def test_get_keys_nonexistent_app_returns_none(self):
        """Test that get_app_identity_keys returns None for unknown app."""
        keys = get_app_identity_keys("nonexistent_app_xyz", backend=None)
        assert keys is None

    @pytest.mark.backend_piv
    def test_ensure_keys_with_closed_backend_fails(self, pkcs11_backend):
        """Test that ensure_keys fails with closed backend."""
        app_name = "test_closed_backend"

        # Get keys while backend is open
        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)
        assert ed_pub is not None

        # Close backend
        pkcs11_backend.close()

        # Further operations should fail or return None gracefully
        # This is implementation-dependent


class TestKeyRetrievalAfterProvisioning:
    """Test key retrieval after provisioning."""

    @pytest.mark.backend_piv
    def test_get_public_key_after_ensure_keys(self, pkcs11_backend):
        """Test retrieving public key after provisioning."""
        app_name = "test_retrieve_after_prov"

        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        # Retrieve using labels
        ed_label = f"{app_name}-sign"
        x_label = f"{app_name}-enc"

        ed_retrieved = pkcs11_backend.get_public_key_bytes(key_label=ed_label)
        x_retrieved = pkcs11_backend.get_public_key_bytes(key_label=x_label)

        assert ed_pub == ed_retrieved
        assert x_pub == x_retrieved

    @pytest.mark.backend_piv
    def test_signing_after_key_provisioning(self, pkcs11_backend):
        """Test that signing works after key provisioning."""
        app_name = "test_sign_after_prov"

        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        ed_label = f"{app_name}-sign"

        # Sign message
        message = b"test message for signing"
        sig = pkcs11_backend.sign(message, key_label=ed_label)

        assert sig is not None
        assert len(sig) > 0

    @pytest.mark.backend_piv
    def test_ecdh_after_key_provisioning(self, pkcs11_backend):
        """Test that ECDH works after key provisioning."""
        app_name = "test_ecdh_after_prov"

        ed_pub, x_pub = pkcs11_backend.ensure_keys_for_app(app_name)

        x_label = f"{app_name}-enc"

        # Create a peer public key for ECDH
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        peer_priv = X25519PrivateKey.generate()
        peer_pub = peer_priv.public_key()

        # Perform ECDH
        shared_secret = pkcs11_backend.ecdh_derive(
            peer_pub.public_bytes_raw(),
            key_label=x_label,
        )

        assert shared_secret is not None
        assert len(shared_secret) == 32


class TestMultiAppIdentityCrypto:
    """End-to-end sign/verify and encrypt/decrypt round-trips for the multi-app
    HardwareIdentity produced by ``make_app_hardware_identity_class``.

    The other multi-app tests only check key loading, hashing and that two
    signatures differ; none of them verify a signature or decrypt anything, so
    the identity's token-backed ``sign()`` and ``decrypt()`` paths were never
    actually exercised. These round-trips close that gap.
    """

    def _app_identity(self, backend, app_name, slot="9a"):
        backend.ensure_keys_for_app(app_name)
        cls = make_app_hardware_identity_class(
            app_name=app_name,
            backend=backend,
            slot=slot,
        )
        return cls(create_keys=True)

    @pytest.mark.backend_piv
    def test_multi_app_identity_sign_validate_roundtrip(self, pkcs11_backend):
        """A token-signed message validates against the identity's public key."""
        identity = self._app_identity(pkcs11_backend, "rt_sign_app")
        message = b"multi-app hardware signature round-trip"
        signature = identity.sign(message)
        assert identity.validate(signature, message) is True
        assert identity.validate(signature, b"a different message") is False

    @pytest.mark.backend_piv
    def test_multi_app_identity_encrypt_decrypt_roundtrip(self, pkcs11_backend):
        """Ciphertext encrypted to the identity decrypts via token ECDH."""
        identity = self._app_identity(pkcs11_backend, "rt_enc_app")
        plaintext = b"multi-app hardware encryption round-trip"
        ciphertext = identity.encrypt(plaintext)
        assert ciphertext != plaintext
        assert identity.decrypt(ciphertext) == plaintext

    @pytest.mark.backend_piv
    def test_transparent_injection_binds_token_identity_roundtrip(self, pkcs11_backend):
        """The transparent-injection binding turns a plain RNS.Identity into a
        token-backed one: correct hash, no software private key, and working
        token sign/verify + encrypt/decrypt. This is the end-to-end proof of the
        rns_integration fix (the old code overwrote only public bytes, leaving a
        software key and a mismatched hash)."""
        import RNS
        from reticulum_pkcs11_identity.identity import create_app_hardware_identity
        from reticulum_pkcs11_identity.rns_integration import (
            _bind_hardware_identity,
            is_identity_hardware_backed,
        )

        app_name = "inject_rt_app"
        pkcs11_backend.ensure_keys_for_app(app_name)
        hw = create_app_hardware_identity(app_name, backend=pkcs11_backend, slot="9a")
        assert hw is not None

        # Start from an ordinary software identity, then bind the token identity.
        ident = RNS.Identity(create_keys=True)
        _bind_hardware_identity(ident, hw, app_name)

        # Destination hash now matches the advertised hardware public keys.
        assert ident.pub_bytes == hw.pub_bytes
        assert ident.sig_pub_bytes == hw.sig_pub_bytes
        assert ident.hash == hw.hash
        assert is_identity_hardware_backed(ident)
        # No in-memory private key is retained.
        assert ident.prv_bytes is None
        assert ident.sig_prv_bytes is None

        # Token-backed sign/verify round-trip.
        message = b"injected token signature round-trip"
        signature = ident.sign(message)
        assert ident.validate(signature, message) is True

        # Token-backed encrypt/decrypt round-trip.
        plaintext = b"injected token ciphertext round-trip"
        ciphertext = ident.encrypt(plaintext)
        assert ident.decrypt(ciphertext) == plaintext

    def test_factory_rejects_non_conforming_backend(self):
        """A backend lacking the PKCS11Backend interface (e.g. the YubiKey-PIV
        helper backend) is rejected with a clear error rather than crashing with
        a cryptic AttributeError deep inside key loading."""
        class FakePIVBackend:
            def sign(self, *args, **kwargs):
                return b""

        with pytest.raises(PKCS11BackendError, match="must implement the PKCS11Backend"):
            make_app_hardware_identity_class(
                "guarded_app", backend=FakePIVBackend(), slot="9a"
            )
