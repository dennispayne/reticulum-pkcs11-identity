"""Hardware-backed RNS identity bootstrap helpers.

The hardware identity is generic: a single token-resident keypair (Ed25519 for
signing, X25519 for encryption) that every Reticulum app shares. Distinct
per-app addresses come from RNS aspects, not from separate keys, so nothing
here is specific to any one app (such as LXMF).

The token PIN is never read from or written to a configuration file. It is
collected at session start -- by the token's own PIN pad if it has one
(protected authentication path), otherwise by an interactive prompt or a PIN
supplied programmatically by the caller.
"""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass

from .backend import PKCS11Backend
from .exceptions import PKCS11KeyNotFoundError


@dataclass(frozen=True)
class HardwareIdentityConfig:
    module_path: str
    token_label: str
    sign_key_label: str = "rns-sign"
    enc_key_label: str = "rns-enc"
    sign_key_id: bytes | None = None
    enc_key_id: bytes | None = None


@dataclass
class HardwareIdentityHandle:
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


def load_hardware_identity_binding(config_path: str | None = None) -> HardwareIdentityConfig | None:
    """Read the token/key binding from the ``[hardware_identity]`` config section.

    Returns ``None`` when no Reticulum config file is found or the section does
    not name both a provider module and a token label. A PIN is never read from
    the config file -- it is collected at session start.
    """
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
    if not parser.has_section("hardware_identity"):
        return None

    section = parser["hardware_identity"]
    module_path = section.get("provider", fallback="").strip()
    token_label = section.get("token_label", fallback="").strip()
    if not module_path or not token_label:
        return None

    return HardwareIdentityConfig(
        module_path=module_path,
        token_label=token_label,
        sign_key_label=section.get("sign_key_label", fallback="rns-sign").strip() or "rns-sign",
        enc_key_label=section.get("enc_key_label", fallback="rns-enc").strip() or "rns-enc",
        sign_key_id=_resolve_key_id(section.get("sign_key_id", fallback=None)),
        enc_key_id=_resolve_key_id(section.get("enc_key_id", fallback=None)),
    )


def _ensure_keys(backend: PKCS11Backend, config: HardwareIdentityConfig) -> None:
    try:
        backend.get_public_key_bytes(key_label=config.sign_key_label)
    except PKCS11KeyNotFoundError:
        backend.generate_ed25519_keypair(label=config.sign_key_label, key_id=config.sign_key_id)
    try:
        backend.get_public_key_bytes(key_label=config.enc_key_label)
    except PKCS11KeyNotFoundError:
        backend.generate_x25519_keypair(label=config.enc_key_label, key_id=config.enc_key_id)


def create_hardware_identity(
    config: HardwareIdentityConfig,
    *,
    pin: str | None = None,
    pin_callback=None,
    ensure_keys: bool = True,
) -> HardwareIdentityHandle:
    """Open the token and build the hardware-backed RNS identity.

    The PIN is resolved by the backend at session start (the token's own PIN
    pad, an interactive prompt, or the optional *pin* / *pin_callback* supplied
    by the caller). It is never read from configuration.
    """
    backend = PKCS11Backend(module_path=config.module_path, token_label=config.token_label)
    backend.open_session(
        pin=pin,
        pin_callback=pin_callback,
        prompt=f"PIN for PKCS#11 token '{config.token_label}': ",
    )

    try:
        if ensure_keys:
            _ensure_keys(backend, config)

        from .identity import make_hardware_identity_class

        identity_class = make_hardware_identity_class(
            backend=backend,
            sign_key_label=config.sign_key_label,
            enc_key_label=config.enc_key_label,
            sign_key_id=config.sign_key_id,
            enc_key_id=config.enc_key_id,
        )
        identity = identity_class(create_keys=True)
        return HardwareIdentityHandle(backend=backend, identity=identity)
    except Exception:
        backend.close()
        raise
