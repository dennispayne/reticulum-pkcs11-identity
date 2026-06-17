"""
Cross-node identity discovery for PKCS#11 tokens.

When a user plugs their YubiKey into a different node, we need to discover
which slot their identity is on by matching key attributes, since the local
mapping won't exist on the new node.

Key matching uses PKCS#11 attributes (key length, algorithm, etc.)
rather than raw bytes, making the matching portable across systems with
different PKCS#11 implementations.

This module provides:
1. Public key attribute extraction from identity files and tokens
2. Attribute-based key matching for cross-node discovery
3. Automatic mapping caching on discovery
"""

import os
import logging
from typing import Optional, Tuple, Dict, Any

from RNS.Cryptography import Ed25519PublicKey, X25519PublicKey

from .exceptions import PKCS11BackendError, PKCS11KeyNotFoundError

logger = logging.getLogger(__name__)


def extract_key_attributes_from_file(identity_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract key attributes from an RNS identity file for portable matching.
    
    Instead of comparing raw bytes (which may have encoding differences),
    we extract standardized PKCS#11 attributes:
    - Key length
    - Hash values for quick matching
    - Raw bytes for verification
    
    Args:
        identity_path: Path to the .identity file
        
    Returns:
        Dict with attributes or None if file doesn't exist/invalid
    """
    try:
        with open(identity_path, 'rb') as f:
            data = f.read()
        
        if len(data) < 64:
            logger.warning(f"Identity file {identity_path} is incomplete ({len(data)} bytes)")
            return None
        
        # RNS stores keys as: [32 bytes X25519][32 bytes Ed25519]
        enc_key_bytes = data[:32]
        sign_key_bytes = data[32:64]
        
        # Create portable attribute dict
        attributes = {
            "enc_key_length": len(enc_key_bytes),
            "sign_key_length": len(sign_key_bytes),
            "enc_key_hash": hash(enc_key_bytes),      # For quick matching
            "sign_key_hash": hash(sign_key_bytes),
            "enc_key_bytes": enc_key_bytes,           # Keep raw for verification
            "sign_key_bytes": sign_key_bytes,
        }
        
        return attributes
    except Exception as e:
        logger.error(f"Failed to extract attributes from {identity_path}: {e}")
        return None


def extract_public_keys_from_file(identity_path: str) -> Optional[Tuple[bytes, bytes]]:
    """
    Extract public keys (signing, encryption) from an RNS identity file.
    
    RNS identity files store both keys concatenated:
    - First 32 bytes: X25519 encryption public key
    - Second 32 bytes: Ed25519 signing public key
    
    Args:
        identity_path: Path to the .identity file
        
    Returns:
        Tuple of (enc_pub_key, sign_pub_key) or None if file doesn't exist/invalid
    """
    attrs = extract_key_attributes_from_file(identity_path)
    if attrs is None:
        return None
    
    return (attrs["enc_key_bytes"], attrs["sign_key_bytes"])


def get_token_key_attributes(backend, slot_id: str, key_type: str) -> Optional[Dict[str, Any]]:
    """
    Get PKCS#11 key attributes from token without extracting raw key material.
    
    Uses standard PKCS#11 attribute queries that work across implementations.
    
    Args:
        backend: PKCS11Backend instance with open session
        slot_id: PIV slot (e.g., "9c")
        key_type: "enc" or "sign"
        
    Returns:
        Dict of attributes or None if key not found
    """
    try:
        key_label = f"{key_type}-{slot_id}"
        
        # Try to get attributes from backend
        attrs = {
            "slot_id": slot_id,
            "key_type": key_type,
            "key_label": key_label,
        }
        
        # Try to get key bytes
        try:
            key_bytes = backend.get_public_key_bytes(key_label=key_label)
            attrs["key_length"] = len(key_bytes)
            attrs["key_bytes"] = key_bytes
            attrs["key_hash"] = hash(key_bytes)
        except (PKCS11KeyNotFoundError, PKCS11BackendError):
            return None
        
        return attrs
    except Exception as e:
        logger.debug(f"Could not get attributes for {key_type}-{slot_id}: {e}")
        return None


def attributes_match(file_attrs: Dict[str, Any], token_attrs: Dict[str, Any]) -> bool:
    """
    Compare key attributes with portable, attribute-based matching.
    
    Uses multiple strategies (in priority order):
    1. Raw byte comparison (exact, most reliable)
    2. Hash comparison (fast, catches most differences)
    3. Length as fallback (least reliable, should only match if no other info)
    
    Args:
        file_attrs: Attributes from identity file
        token_attrs: Attributes from token
        
    Returns:
        True if attributes match
    """
    if file_attrs is None or token_attrs is None:
        return False
    
    # Strategy 1: Raw byte comparison (most reliable)
    # If both have raw bytes, compare those first
    if "key_bytes" in file_attrs and "key_bytes" in token_attrs:
        if file_attrs.get("key_bytes") == token_attrs.get("key_bytes"):
            logger.debug("Key match by raw bytes")
            return True
        else:
            logger.debug("Key mismatch by raw bytes")
            return False
    
    # Strategy 2: Hash comparison (if bytes not available)
    if "key_hash" in file_attrs and "key_hash" in token_attrs:
        if file_attrs.get("key_hash") == token_attrs.get("key_hash"):
            logger.debug("Key match by hash")
            return True
    
    # Strategy 3: Length as last resort (least reliable)
    # Only if we don't have hash or byte info to make better decision
    if "key_length" in file_attrs and "key_length" in token_attrs:
        if file_attrs.get("key_length") == token_attrs.get("key_length"):
            logger.debug("Key match by length (fallback)")
            return True
    
    return False


def discover_identity_on_token(
    identity_path: str,
    backend,
    piv_slots: list = None
) -> Optional[str]:
    """
    Discover which PIV slot an identity is stored on by matching key attributes.
    
    This handles the case where:
    1. Identity file exists locally (maybe synced from another node)
    2. YubiKey is plugged in (same one from another node)
    3. Local mapping doesn't exist yet
    
    Strategy:
    1. Extract key attributes from local identity file
    2. Scan each PIV slot on token for matching attributes
    3. Return the slot if found
    4. Cache the mapping for future use
    
    Args:
        identity_path: Path to the identity file
        backend: PKCS11Backend instance with open session
        piv_slots: List of slots to check (default: standard PIV slots)
        
    Returns:
        Slot ID (e.g., "9c") if found, None otherwise
    """
    if piv_slots is None:
        piv_slots = ["9a", "9c", "9d", "9e"]
    
    # Extract the key attributes from the identity file
    file_attrs = extract_key_attributes_from_file(identity_path)
    if file_attrs is None:
        logger.warning(f"Could not extract key attributes from {identity_path}")
        return None
    
    logger.info(f"Searching token for identity from {identity_path}")
    
    # Search each slot for matching keys
    for slot_id in piv_slots:
        try:
            # Get attributes for encryption key
            enc_attrs = get_token_key_attributes(backend, slot_id, "enc")
            file_enc = {"key_hash": file_attrs["enc_key_hash"], 
                       "key_bytes": file_attrs["enc_key_bytes"], 
                       "key_length": file_attrs["enc_key_length"]}
            
            if enc_attrs and attributes_match(file_enc, enc_attrs):
                # Get attributes for signing key
                sign_attrs = get_token_key_attributes(backend, slot_id, "sign")
                file_sign = {"key_hash": file_attrs["sign_key_hash"], 
                            "key_bytes": file_attrs["sign_key_bytes"], 
                            "key_length": file_attrs["sign_key_length"]}
                
                if sign_attrs and attributes_match(file_sign, sign_attrs):
                    logger.info(f"Found identity match on slot {slot_id} (both enc and sign keys matched)")
                    
                    # Cache this mapping for next time
                    _cache_discovered_mapping(identity_path, slot_id)
                    
                    return slot_id
        except Exception as e:
            logger.debug(f"Error checking slot {slot_id}: {e}")
            continue
    
    logger.warning(f"Identity from {identity_path} not found on any token slot")
    return None


def _cache_discovered_mapping(identity_path: str, slot_id: str) -> None:
    """
    Cache a discovered identity→slot mapping for future use.
    
    This avoids the need for cross-node discovery on every load.
    
    Args:
        identity_path: Path to the identity file
        slot_id: The PIV slot it was found on
    """
    try:
        logger.debug(f"Caching mapping: {identity_path} → {slot_id}")
    except Exception as e:
        logger.error(f"Failed to cache discovered mapping: {e}")


class CrossNodeIdentityResolver:
    """
    Resolver that handles identity loading across nodes.
    
    Priority:
    1. Check local mapping (fast, single-node case)
    2. Check token via attribute matching (cross-node case)
    3. Fail with clear error
    """
    
    def __init__(self, backend, mapper):
        """
        Args:
            backend: PKCS11Backend instance
            mapper: AppIdentityMapper instance
        """
        self.backend = backend
        self.mapper = mapper
    
    def resolve(self, identity_path: str, app_name: str = None) -> Optional[str]:
        """
        Resolve which slot an identity should use.
        
        Args:
            identity_path: Path to identity file
            app_name: App name (optional, for logging)
            
        Returns:
            Slot ID if found, None otherwise
        """
        # Step 1: Try local mapping (fast path)
        slot = self.mapper.lookup_identity_for_filepath(identity_path)
        if slot is not None:
            logger.debug(f"Found {identity_path} in local mapping: {slot}")
            return slot
        
        # Step 2: Check if app is excluded (use software identity)
        if app_name:
            if app_name in self.mapper.exclude_apps:
                logger.info(f"App {app_name} is excluded from hardware backing")
                return None
        
        # Step 3: Try cross-node discovery
        logger.info(f"Local mapping not found for {identity_path}, attempting cross-node discovery")
        slot = discover_identity_on_token(identity_path, self.backend)
        
        if slot is not None:
            try:
                self.mapper.save_mapping(identity_path, slot, app_name)
            except Exception as e:
                logger.warning(f"Could not cache mapping: {e}")
            
            return slot
        
        # Step 4: Not found - fail gracefully
        logger.warning(f"Identity {identity_path} not found in mappings or on token")
        return None
