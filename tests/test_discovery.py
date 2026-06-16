import pkcs11
import pytest

from reticulum_pkcs11_identity.discovery import (
    enumerate_token_inventory,
    format_token_inventory,
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
