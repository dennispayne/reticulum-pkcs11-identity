"""
Tests for cross-node identity discovery.

Handles the scenario where a YubiKey is set up on Node A, then plugged
into Node B where the local mapping doesn't exist.
"""

import os
import tempfile
import pytest
from unittest.mock import Mock, patch

from reticulum_pkcs11_identity.cross_node_discovery import (
    extract_public_keys_from_file,
    discover_identity_on_token,
    CrossNodeIdentityResolver,
)
from reticulum_pkcs11_identity.experimental.app_identity import AppIdentityMapper


class TestPublicKeyExtraction:
    """Test extracting public keys from identity files."""
    
    def test_extract_keys_from_valid_identity(self):
        """Test extracting keys from a valid RNS identity file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = os.path.join(tmpdir, "test.identity")
            
            # Create a mock identity file (64 bytes: 32 enc + 32 sign)
            enc_key = b'\xAA' * 32
            sign_key = b'\xBB' * 32
            
            with open(identity_path, 'wb') as f:
                f.write(enc_key + sign_key)
            
            # Extract
            keys = extract_public_keys_from_file(identity_path)
            
            assert keys is not None
            assert keys[0] == enc_key
            assert keys[1] == sign_key
    
    def test_extract_keys_from_missing_file(self):
        """Test extraction from non-existent file returns None."""
        keys = extract_public_keys_from_file("/nonexistent/path.identity")
        assert keys is None
    
    def test_extract_keys_from_truncated_file(self):
        """Test extraction from incomplete file returns None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = os.path.join(tmpdir, "truncated.identity")
            
            # Write only 32 bytes (incomplete)
            with open(identity_path, 'wb') as f:
                f.write(b'\xAA' * 32)
            
            keys = extract_public_keys_from_file(identity_path)
            assert keys is None


class TestCrossNodeDiscovery:
    """Test discovering identity on token from different node."""
    
    def test_discover_identity_matching_keys(self):
        """Test discovery finds identity when keys match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = os.path.join(tmpdir, "meshchat.identity")
            
            # Create identity file with test keys
            enc_key = b'\xAA' * 32
            sign_key = b'\xBB' * 32
            with open(identity_path, 'wb') as f:
                f.write(enc_key + sign_key)
            
            # Mock backend that returns matching keys
            backend = Mock()
            
            def mock_get_keys(key_label):
                if key_label == "enc-9c":
                    return enc_key
                elif key_label == "sign-9c":
                    return sign_key
                raise Exception("Key not found")
            
            backend.get_public_key_bytes = mock_get_keys
            
            # Discover
            slot = discover_identity_on_token(identity_path, backend, piv_slots=["9c"])
            
            assert slot == "9c"
    
    def test_discover_identity_no_match(self):
        """Test discovery returns None when keys don't match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = os.path.join(tmpdir, "meshchat.identity")
            
            # Create identity file with specific keys
            enc_key = b'\xAA' * 32
            sign_key = b'\xAA' * 32
            with open(identity_path, 'wb') as f:
                f.write(enc_key + sign_key)
            
            # Mock backend with different keys
            backend = Mock()
            backend.get_public_key_bytes.return_value = b'\xBB' * 32  # Different from file
            
            slot = discover_identity_on_token(identity_path, backend, piv_slots=["9c"])
            
            assert slot is None
    
    def test_discover_searches_multiple_slots(self):
        """Test discovery searches multiple slots until match found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = os.path.join(tmpdir, "sideband.identity")
            
            # Key is on slot 9d
            enc_key = b'\xCC' * 32
            sign_key = b'\xDD' * 32
            with open(identity_path, 'wb') as f:
                f.write(enc_key + sign_key)
            
            # Mock backend
            backend = Mock()
            
            def mock_get_keys(key_label):
                # Slot 9c has wrong keys
                if key_label == "enc-9c":
                    return b'\xBB' * 32
                elif key_label == "sign-9c":
                    return b'\xBB' * 32
                # Slot 9d has correct keys
                elif key_label == "enc-9d":
                    return enc_key
                elif key_label == "sign-9d":
                    return sign_key
                raise Exception("Key not found")
            
            backend.get_public_key_bytes = mock_get_keys
            
            slot = discover_identity_on_token(
                identity_path, backend,
                piv_slots=["9c", "9d", "9e"]
            )
            
            assert slot == "9d"


class TestCrossNodeIdentityResolver:
    """Test full resolver with fallback from local mapping to discovery."""
    
    def test_resolve_uses_local_mapping_first(self):
        """Test resolver uses fast local mapping when available."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mapper = AppIdentityMapper(config_dir=tmpdir)
            backend = Mock()
            resolver = CrossNodeIdentityResolver(backend, mapper)
            
            # Manually add a mapping
            identity_path = "/home/user/.reticulum/storage/identities/app.identity"
            mapper._mapping[identity_path] = {"slot": "9a", "app_name": "app"}
            mapper._slot_apps["9a"] = ["app"]
            
            # Resolve should return 9a without calling backend
            slot = resolver.resolve(identity_path, "app")
            
            assert slot == "9a"
            # Verify backend was not called
            backend.get_public_key_bytes.assert_not_called()
    
    def test_resolve_falls_back_to_discovery(self):
        """Test resolver falls back to discovery when local mapping missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create identity file
            identity_path = os.path.join(tmpdir, "app.identity")
            with open(identity_path, 'wb') as f:
                f.write(b'\xAA' * 64)
            
            mapper = AppIdentityMapper(config_dir=tmpdir)
            backend = Mock()
            resolver = CrossNodeIdentityResolver(backend, mapper)
            
            # Mock discovery to succeed
            with patch('reticulum_pkcs11_identity.cross_node_discovery.discover_identity_on_token') as mock_discover:
                mock_discover.return_value = "9d"
                
                slot = resolver.resolve(identity_path, "app")
                
                assert slot == "9d"
                mock_discover.assert_called_once()
    
    def test_resolve_respects_exclusion_list(self):
        """Test resolver respects app exclusion list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity_path = "/home/user/.reticulum/storage/identities/debug.identity"
            
            mapper = AppIdentityMapper(
                config_dir=tmpdir,
                exclude_apps=["debug"]
            )
            backend = Mock()
            resolver = CrossNodeIdentityResolver(backend, mapper)
            
            # Even with a mapping, excluded app returns None
            mapper._mapping[identity_path] = {"slot": "9a", "app_name": "debug"}
            
            slot = resolver.resolve(identity_path, "debug")
            
            assert slot is None
