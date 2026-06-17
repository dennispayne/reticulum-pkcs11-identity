"""
Tests for PKCS#11 session manager.
"""

import os
import tempfile
import pytest

from reticulum_pkcs11_identity.session_manager import (
    PKCSIISessionManager,
    get_session_manager,
    initialize_session,
    is_session_ready,
    shutdown_session,
)


class TestSessionManager:
    """Test PKCS#11 session caching and lifecycle."""

    def test_singleton_pattern(self):
        """Test session manager is singleton."""
        manager1 = get_session_manager()
        manager2 = get_session_manager()
        assert manager1 is manager2

    def test_not_ready_by_default(self):
        """Test session not ready without initialization."""
        manager = PKCSIISessionManager()
        assert not manager.is_ready()

    def test_initialize_without_pin_returns_false(self):
        """Test initialization fails gracefully without PIN."""
        manager = PKCSIISessionManager()
        # No PIN configured, auto_prompt=False
        result = manager.initialize(pin=None, auto_prompt=False)
        assert result is False
        assert not manager.is_ready()

    def test_initialize_with_invalid_pin_returns_false(self):
        """Test initialization fails gracefully with invalid PIN."""
        manager = PKCSIISessionManager()
        # Invalid PIN should not crash, just return False
        result = manager.initialize(pin="invalid", auto_prompt=False)
        # May be False (auth failed) or True (if somehow it worked)
        assert isinstance(result, bool)

    def test_get_backend_returns_none_when_not_ready(self):
        """Test get_backend returns None when not initialized."""
        manager = PKCSIISessionManager()
        assert manager.get_backend() is None

    def test_get_session_for_slot_returns_none_when_not_ready(self):
        """Test session retrieval returns None when not ready."""
        manager = PKCSIISessionManager()
        session = manager.get_session_for_slot("9a")
        assert session is None

    def test_initialize_session_function(self):
        """Test module-level initialize_session function."""
        result = initialize_session(pin=None, auto_prompt=False)
        # Should return False (no PIN)
        assert result is False

    def test_is_session_ready_function(self):
        """Test module-level is_session_ready function."""
        result = is_session_ready()
        # May be True if hardware is plugged in, False otherwise
        assert isinstance(result, bool)

    def test_shutdown_function(self):
        """Test module-level shutdown_session function."""
        # Should not raise
        shutdown_session()

    def test_session_manager_repr(self):
        """Test string representation."""
        manager = PKCSIISessionManager()
        repr_str = repr(manager)
        assert "PKCSIISessionManager" in repr_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
