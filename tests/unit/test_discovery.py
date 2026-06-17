import pkcs11
import pytest

from reticulum_pkcs11_identity.discovery import (
    discover_pkcs11_modules,
    enumerate_token_inventory,
    format_token_inventory,
    has_ed25519_key,
    has_x25519_key,
    list_tokens,
    probe_piv_slots,
)


class _FakeKey:
    pass


class _FakeSession:
    def __init__(self, key_labels):
        self._labels = set(key_labels)

    def get_key(self, object_class=None, key_type=None, label=None):
        if label not in self._labels:
            raise pkcs11.exceptions.NoSuchKey()
        return _FakeKey()

    def close(self):
        return None


class _FakeToken:
    def __init__(self, label, serial, key_labels):
        self.label = label
        self.serial = serial
        self._key_labels = key_labels

    def open(self, rw=False):
        return _FakeSession(self._key_labels)


class _FakeSlot:
    def __init__(self, slot_id, token):
        self.slot_id = slot_id
        self._token = token

    def get_token(self):
        return self._token


class _FakeLib:
    def __init__(self, slots):
        self._slots = slots

    def get_slots(self, token_present=True):
        assert token_present is True
        return self._slots


@pytest.mark.discovery
def test_enumerate_token_inventory_detects_ready_and_partial(monkeypatch):
    module_a = "/tmp/libsofthsm2.so"
    module_b = "/tmp/opensc-pkcs11.so"

    libs = {
        module_a: _FakeLib([
            _FakeSlot(1, _FakeToken("SoftToken", "SER-1", ["lxmf-sign", "lxmf-enc"])),
        ]),
        module_b: _FakeLib([
            _FakeSlot(2, _FakeToken("YubiToken", "SER-2", ["lxmf-sign"])),
        ]),
    }

    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    rows = enumerate_token_inventory(module_paths=[module_b, module_a])

    assert len(rows) == 2

    soft = next(row for row in rows if row["token_label"] == "SoftToken")
    yubi = next(row for row in rows if row["token_label"] == "YubiToken")

    assert soft["provider_hint"] == "SoftHSM2"
    assert soft["provider_type"] == "software"
    assert soft["identity_status"] == "ready"
    assert soft["has_sign_key"] is True
    assert soft["has_enc_key"] is True

    assert yubi["provider_hint"] == "OpenSC / Smartcard"
    assert yubi["provider_type"] == "hardware"
    assert yubi["identity_status"] == "partial"
    assert yubi["has_sign_key"] is True
    assert yubi["has_enc_key"] is False


@pytest.mark.discovery
def test_enumerate_token_inventory_prioritizes_hardware_over_software(monkeypatch):
    module_soft = "/tmp/libsofthsm2.so"
    module_hw = "/tmp/opensc-pkcs11.so"

    libs = {
        module_soft: _FakeLib([
            _FakeSlot(1, _FakeToken("SoftToken", "SER-1", ["lxmf-sign", "lxmf-enc"])),
        ]),
        module_hw: _FakeLib([
            _FakeSlot(2, _FakeToken("YubiToken", "SER-2", ["lxmf-sign", "lxmf-enc"])),
        ]),
    }

    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    rows = enumerate_token_inventory(module_paths=[module_soft, module_hw])

    assert len(rows) == 2
    assert rows[0]["provider_type"] == "hardware"
    assert rows[0]["token_label"] == "YubiToken"
    assert rows[1]["provider_type"] == "software"
    assert rows[1]["token_label"] == "SoftToken"


@pytest.mark.discovery
def test_enumerate_token_inventory_filters_by_token_label(monkeypatch):
    module = "/tmp/libsofthsm2.so"
    libs = {
        module: _FakeLib([
            _FakeSlot(1, _FakeToken("KeepMe", "SER-1", ["lxmf-sign", "lxmf-enc"])),
            _FakeSlot(2, _FakeToken("DropMe", "SER-2", ["lxmf-sign", "lxmf-enc"])),
        ])
    }

    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    rows = enumerate_token_inventory(module_paths=[module], token_label="KeepMe")

    assert len(rows) == 1
    assert rows[0]["token_label"] == "KeepMe"

@pytest.mark.discovery

def test_format_token_inventory_includes_provider_and_status():
    text = format_token_inventory(
        [
            {
                "provider_hint": "SoftHSM2",
                "provider_type": "software",
                "module_path": "/tmp/libsofthsm2.so",
                "slot_id": 1,
                "token_label": "SoftToken",
                "serial": "SER-1",
                "identity_status": "ready",
                "has_sign_key": True,
                "has_enc_key": True,
            }
        ]
    )

    assert "provider=SoftHSM2" in text
    assert "(software)" in text
    assert "status=ready" in text
    assert "sign=True, enc=True" in text


# ============================================================================
# PIV Slot Discovery Tests
# ============================================================================


class _FakePIVKey:
    """Fake PKCS#11 key object with EC_PARAMS attribute."""
    def __init__(self, ec_params):
        self._ec_params = ec_params

    def get(self, attr):
        from pkcs11 import Attribute
        if attr == Attribute.EC_PARAMS:
            return self._ec_params
        raise KeyError(f"Attribute {attr} not available")


class _FakePIVSession:
    """Fake PKCS#11 session for PIV testing."""
    def __init__(self, keys_by_oid=None):
        self._keys = keys_by_oid or {}

    def get_objects(self, template):
        """Return keys matching template."""
        keys = []
        for oid, key_data in self._keys.items():
            keys.append(_FakePIVKey(key_data))
        return keys


@pytest.mark.discovery
class TestDiscoverPKCS11Modules:
    def test_discover_modules_returns_empty_list_when_no_modules_exist(self):
        modules = discover_pkcs11_modules(additional_paths=["/nonexistent/lib.so"])
        assert isinstance(modules, list)

    def test_discover_modules_includes_existing_files(self, tmp_path):
        lib = tmp_path / "libfake.so"
        lib.touch()
        modules = discover_pkcs11_modules(additional_paths=[str(lib)])
        assert str(lib) in modules

    def test_discover_modules_excludes_nonexistent_files(self):
        modules = discover_pkcs11_modules(additional_paths=["/nonexistent/lib.so"])
        assert "/nonexistent/lib.so" not in modules

    def test_discover_modules_deduplicates_paths(self, tmp_path):
        lib = tmp_path / "lib.so"
        lib.touch()
        path = str(lib)
        modules = discover_pkcs11_modules(additional_paths=[path, path])
        assert modules.count(path) == 1


@pytest.mark.discovery
class TestListTokens:
    def test_list_tokens_returns_empty_on_module_load_failure(self):
        tokens = list_tokens("/nonexistent/lib.so")
        assert tokens == []

    def test_list_tokens_returns_token_info(self, monkeypatch):
        fake_token = _FakeToken("TestToken", "SER001", [])
        fake_slot = _FakeSlot(1, fake_token)
        fake_lib = _FakeLib([fake_slot])

        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)

        tokens = list_tokens("/fake/lib.so")

        assert len(tokens) == 1
        assert tokens[0]["token_label"] == "TestToken"
        assert tokens[0]["serial"] == "SER001"
        assert tokens[0]["slot_id"] == 1

    def test_list_tokens_returns_empty_on_slot_enumeration_failure(self, monkeypatch):
        fake_lib = _FakeLib([])
        fake_lib.get_slots = lambda **_: (_ for _ in ()).throw(RuntimeError("slots failed"))

        monkeypatch.setattr(pkcs11, "lib", lambda _: fake_lib)

        tokens = list_tokens("/fake/lib.so")
        assert tokens == []


@pytest.mark.discovery
class TestHasEd25519Key:
    def test_has_ed25519_key_returns_false_for_invalid_slot(self):
        session = _FakePIVSession()
        assert has_ed25519_key(session, "invalid") is False

    def test_has_ed25519_key_returns_false_when_no_keys_present(self):
        session = _FakePIVSession()
        assert has_ed25519_key(session, "9a") is False

    def test_has_ed25519_key_returns_true_for_ed25519_oid(self):
        ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
        session = _FakePIVSession({"ed25519": ed25519_oid})
        assert has_ed25519_key(session, "9a") is True

    def test_has_ed25519_key_returns_false_for_x25519_oid(self):
        x25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])
        session = _FakePIVSession({"x25519": x25519_oid})
        assert has_ed25519_key(session, "9a") is False

    def test_has_ed25519_key_returns_false_on_session_error(self):
        class FailingSession:
            def get_objects(self, template):
                raise RuntimeError("Session error")

        session = FailingSession()
        assert has_ed25519_key(session, "9a") is False


@pytest.mark.discovery
class TestHasX25519Key:
    def test_has_x25519_key_returns_false_for_invalid_slot(self):
        session = _FakePIVSession()
        assert has_x25519_key(session, "invalid") is False

    def test_has_x25519_key_returns_false_when_no_keys_present(self):
        session = _FakePIVSession()
        assert has_x25519_key(session, "9a") is False

    def test_has_x25519_key_returns_true_for_x25519_oid(self):
        x25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])
        session = _FakePIVSession({"x25519": x25519_oid})
        assert has_x25519_key(session, "9a") is True

    def test_has_x25519_key_returns_false_for_ed25519_oid(self):
        ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
        session = _FakePIVSession({"ed25519": ed25519_oid})
        assert has_x25519_key(session, "9a") is False

    def test_has_x25519_key_returns_false_on_session_error(self):
        class FailingSession:
            def get_objects(self, template):
                raise RuntimeError("Session error")

        session = FailingSession()
        assert has_x25519_key(session, "9a") is False


@pytest.mark.discovery
class TestProbePIVSlots:
    def test_probe_piv_slots_returns_all_slots_as_empty(self):
        session = _FakePIVSession()
        result = probe_piv_slots(session)

        assert "9a" in result
        assert "9c" in result
        assert "9d" in result
        assert "9e" in result

        for slot_id, status in result.items():
            assert status["occupied"] is False
            assert status["has_ed25519"] is False
            assert status["has_x25519"] is False

    def test_probe_piv_slots_detects_ed25519_key(self):
        ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
        session = _FakePIVSession({"ed25519": ed25519_oid})
        result = probe_piv_slots(session)

        # All slots will report occupied because OID is present
        # In real scenario, PIV slot discovery would be more precise
        for slot_id, status in result.items():
            assert status["has_ed25519"] is True
            assert status["occupied"] is True

    def test_probe_piv_slots_detects_x25519_key(self):
        x25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])
        session = _FakePIVSession({"x25519": x25519_oid})
        result = probe_piv_slots(session)

        for slot_id, status in result.items():
            assert status["has_x25519"] is True
            assert status["occupied"] is True

    def test_probe_piv_slots_detects_both_key_types(self):
        ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
        x25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])
        session = _FakePIVSession({
            "ed25519": ed25519_oid,
            "x25519": x25519_oid,
        })
        result = probe_piv_slots(session)

        for slot_id, status in result.items():
            assert status["occupied"] is True
            assert status["has_ed25519"] is True
            assert status["has_x25519"] is True


@pytest.mark.discovery
def test_enumerate_token_inventory_with_empty_module_list(monkeypatch):
    """enumerate_token_inventory with empty list auto-discovers modules."""
    # When module_paths is None or [], it calls discover_module_paths()
    # which may find system modules. We mock both to ensure empty results.
    def mock_discover(*args, **kwargs):
        return []
    
    monkeypatch.setattr(
        "reticulum_pkcs11_identity.discovery.discover_module_paths",
        mock_discover
    )
    
    rows = enumerate_token_inventory(module_paths=[])
    assert rows == []


@pytest.mark.discovery
def test_enumerate_token_inventory_with_missing_keys_sets_partial(monkeypatch):
    """Token with only enc key detected as partial."""
    module = "/tmp/libsofthsm2.so"
    libs = {
        module: _FakeLib([
            _FakeSlot(1, _FakeToken("TestToken", "SER-1", ["lxmf-enc"])),
        ])
    }
    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    rows = enumerate_token_inventory(module_paths=[module])

    assert len(rows) == 1
    assert rows[0]["identity_status"] == "partial"
    assert rows[0]["has_sign_key"] is False
    assert rows[0]["has_enc_key"] is True


@pytest.mark.discovery
def test_enumerate_token_inventory_sorting_order(monkeypatch):
    """Tokens are sorted: hardware before software, then by provider/label/serial."""
    module_soft = "/tmp/libsofthsm2.so"
    module_hw = "/tmp/opensc-pkcs11.so"

    libs = {
        module_soft: _FakeLib([
            _FakeSlot(1, _FakeToken("SoftToken-B", "SER-2", ["lxmf-sign", "lxmf-enc"])),
            _FakeSlot(2, _FakeToken("SoftToken-A", "SER-1", ["lxmf-sign", "lxmf-enc"])),
        ]),
        module_hw: _FakeLib([
            _FakeSlot(3, _FakeToken("HWToken", "SER-3", ["lxmf-sign", "lxmf-enc"])),
        ])
    }

    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    rows = enumerate_token_inventory(module_paths=[module_soft, module_hw])

    # Should have 3 tokens total
    assert len(rows) == 3
    # First should be hardware
    assert rows[0]["provider_type"] == "hardware"
    # Rest should be software, sorted by label
    assert rows[1]["provider_type"] == "software"
    assert rows[1]["token_label"] == "SoftToken-A"
    assert rows[2]["provider_type"] == "software"
    assert rows[2]["token_label"] == "SoftToken-B"


@pytest.mark.discovery
def test_format_token_inventory_with_missing_fields():
    """format_token_inventory handles rows with missing optional fields."""
    rows = [
        {
            "provider_hint": "Unknown",
            "provider_type": "unknown",
            "module_path": "/lib/unknown.so",
            "token_label": None,
            "serial": None,
            "slot_id": None,
            "identity_status": "unknown",
            "has_sign_key": None,
            "has_enc_key": None,
        }
    ]
    text = format_token_inventory(rows)
    
    # Should still format without errors
    assert "[1]" in text
    assert "Unknown" in text


@pytest.mark.discovery
def test_enumerate_token_inventory_token_label_filter_case_sensitive(monkeypatch):
    """Token label filter is case-sensitive."""
    module = "/tmp/libsofthsm2.so"
    libs = {
        module: _FakeLib([
            _FakeSlot(1, _FakeToken("TestToken", "SER-1", ["lxmf-sign", "lxmf-enc"])),
        ])
    }
    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    # Request uppercase, have lowercase - should not match
    rows = enumerate_token_inventory(module_paths=[module], token_label="testtoken")
    assert len(rows) == 0

    # Request exact case - should match
    rows = enumerate_token_inventory(module_paths=[module], token_label="TestToken")
    assert len(rows) == 1


@pytest.mark.discovery
def test_enumerate_token_inventory_custom_key_labels(monkeypatch):
    """enumerate_token_inventory respects custom key labels."""
    module = "/tmp/libsofthsm2.so"
    libs = {
        module: _FakeLib([
            _FakeSlot(1, _FakeToken("Token", "SER-1", ["custom-sign", "custom-enc"])),
        ])
    }
    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    rows = enumerate_token_inventory(
        module_paths=[module],
        sign_key_label="custom-sign",
        enc_key_label="custom-enc",
    )

    assert len(rows) == 1
    assert rows[0]["has_sign_key"] is True
    assert rows[0]["has_enc_key"] is True
    assert rows[0]["identity_status"] == "ready"


@pytest.mark.discovery
def test_enumerate_token_inventory_multiple_modules(monkeypatch):
    """enumerate_token_inventory processes multiple modules."""
    module_a = "/tmp/libsofthsm2.so"
    module_b = "/tmp/opensc-pkcs11.so"
    module_c = "/tmp/libykcs11.so"

    libs = {
        module_a: _FakeLib([
            _FakeSlot(1, _FakeToken("Token-A", "SER-A", ["lxmf-sign", "lxmf-enc"])),
        ]),
        module_b: _FakeLib([
            _FakeSlot(2, _FakeToken("Token-B", "SER-B", ["lxmf-sign"])),
        ]),
        module_c: _FakeLib([
            _FakeSlot(3, _FakeToken("Token-C", "SER-C", ["lxmf-enc"])),
        ])
    }

    monkeypatch.setattr(pkcs11, "lib", lambda path: libs[path])

    rows = enumerate_token_inventory(module_paths=[module_a, module_b, module_c])

    assert len(rows) == 3
    labels = {row["token_label"] for row in rows}
    assert labels == {"Token-A", "Token-B", "Token-C"}
