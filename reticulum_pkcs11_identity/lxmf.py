"""LXMF-focused PKCS#11 identity bootstrap helpers."""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass

from .backend import PKCS11Backend
from .exceptions import PKCS11KeyNotFoundError


@dataclass(frozen=True)
class LXMFHardwareIdentityConfig:
    module_path: str
    token_label: str
    sign_key_label: str = "lxmf-sign"
    enc_key_label: str = "lxmf-enc"
    sign_key_id: bytes | None = None
    enc_key_id: bytes | None = None
    pin: str | None = None
    pin_env: str = "LXMF_PKCS11_PIN"


@dataclass
class LXMFHardwareIdentityHandle:
    backend: PKCS11Backend
    identity: object

    def close(self) -> None:
        self.backend.close()


def _reticulum_config_candidates() -> list[str]:
    env_dir = os.environ.get("RETICULUM_CONFIGDIR")
    home = os.path.expanduser("~")
    candidates: list[str] = []
    if env_dir:
        candidates.append(os.path.join(env_dir, "config"))
    candidates.extend(
        [
            os.path.join(home, ".config", "reticulum", "config"),
            os.path.join(home, ".reticulum", "config"),
            os.path.join(os.sep, "etc", "reticulum", "config"),
        ]
    )
    return candidates


def _resolve_key_id(value: str | None) -> bytes | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped.encode() if stripped else None


def load_lxmf_hardware_identity_config(config_path: str | None = None) -> LXMFHardwareIdentityConfig | None:
    parser = configparser.ConfigParser()
    path = config_path
    if path is None:
        for candidate in _reticulum_config_candidates():
            if os.path.isfile(candidate):
                path = candidate
                break
    if path is None or not os.path.isfile(path):
        return None

    parser.read(path)
    if not parser.has_section("lxmf_pkcs11_identity"):
        return None

    section = parser["lxmf_pkcs11_identity"]
    module_path = section.get("module", fallback="").strip()
    token_label = section.get("token_label", fallback="").strip()
    if not module_path or not token_label:
        return None

    pin_env = section.get("pin_env", fallback="LXMF_PKCS11_PIN").strip() or "LXMF_PKCS11_PIN"
    pin_value = section.get("pin", fallback=None)

    return LXMFHardwareIdentityConfig(
        module_path=module_path,
        token_label=token_label,
        sign_key_label=section.get("sign_key_label", fallback="lxmf-sign").strip() or "lxmf-sign",
        enc_key_label=section.get("enc_key_label", fallback="lxmf-enc").strip() or "lxmf-enc",
        sign_key_id=_resolve_key_id(section.get("sign_key_id", fallback=None)),
        enc_key_id=_resolve_key_id(section.get("enc_key_id", fallback=None)),
        pin=pin_value.strip() if isinstance(pin_value, str) else None,
        pin_env=pin_env,
    )


def _resolve_pin(config: LXMFHardwareIdentityConfig, explicit_pin: str | None) -> str | None:
    if explicit_pin is not None:
        return explicit_pin
    if config.pin is not None:
        return config.pin
    return os.environ.get(config.pin_env)


def _ensure_lxmf_keys(backend: PKCS11Backend, config: LXMFHardwareIdentityConfig) -> None:
    try:
        backend.get_public_key_bytes(key_label=config.sign_key_label)
    except PKCS11KeyNotFoundError:
        backend.generate_ed25519_keypair(label=config.sign_key_label, key_id=config.sign_key_id)
    try:
        backend.get_public_key_bytes(key_label=config.enc_key_label)
    except PKCS11KeyNotFoundError:
        backend.generate_x25519_keypair(label=config.enc_key_label, key_id=config.enc_key_id)


def create_lxmf_hardware_identity(
    config: LXMFHardwareIdentityConfig,
    *,
    pin: str | None = None,
    pin_callback=None,
    ensure_keys: bool = True,
) -> LXMFHardwareIdentityHandle:
    backend = PKCS11Backend(module_path=config.module_path, token_label=config.token_label)
    backend.open_session(
        pin=_resolve_pin(config, pin),
        pin_callback=pin_callback,
        prompt=f"PIN for LXMF PKCS#11 token '{config.token_label}': ",
    )

    try:
        if ensure_keys:
            _ensure_lxmf_keys(backend, config)

        from .identity import make_lxmf_identity_class

        identity_class = make_lxmf_identity_class(
            backend=backend,
            sign_key_label=config.sign_key_label,
            enc_key_label=config.enc_key_label,
            sign_key_id=config.sign_key_id,
            enc_key_id=config.enc_key_id,
        )
        identity = identity_class(create_keys=True)
        return LXMFHardwareIdentityHandle(backend=backend, identity=identity)
    except Exception:
        backend.close()
        raise
