from reticulum_pkcs11_identity.exceptions import PKCS11KeyNotFoundError
from reticulum_pkcs11_identity.patch import _ensure_identity_keys


class _BootstrapBackend:
    def __init__(self, present=None):
        self.present = set(present or [])
        self.generated = []

    def get_public_key_bytes(self, *, key_label):
        if key_label not in self.present:
            raise PKCS11KeyNotFoundError(f"missing {key_label}")
        return b"\x00" * 32

    def generate_ed25519_keypair(self, *, label):
        self.generated.append(("sign", label))
        self.present.add(label)

    def generate_x25519_keypair(self, *, label):
        self.generated.append(("enc", label))
        self.present.add(label)


def test_ensure_identity_keys_creates_missing_keys():
    backend = _BootstrapBackend(present=set())
    cfg = {
        "sign_key_label": "rns-sign",
        "enc_key_label": "rns-enc",
    }

    created = _ensure_identity_keys(backend, cfg)

    assert created == ["rns-sign", "rns-enc"]
    assert backend.generated == [("sign", "rns-sign"), ("enc", "rns-enc")]


def test_ensure_identity_keys_keeps_existing_keys():
    backend = _BootstrapBackend(present={"rns-sign", "rns-enc"})
    cfg = {
        "sign_key_label": "rns-sign",
        "enc_key_label": "rns-enc",
    }

    created = _ensure_identity_keys(backend, cfg)

    assert created == []
    assert backend.generated == []

