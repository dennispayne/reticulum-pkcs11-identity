# Reticulum PKCS#11 Identity - License
#
# Copyright (c) 2024 Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Config-driven monkey-patch for PKCS#11 identity support.

This module is the single integration point between Reticulum and the PKCS#11
backend.  It reads the Reticulum configuration file directly and, when
``identity_backend = pkcs11`` is present in the ``[reticulum]`` section,
replaces ``RNS.Identity`` with :class:`~.identity.HardwareIdentity`.

The patch is **opt-in** and **explicitly documented as a workaround** until the
Reticulum community decides whether to adopt a pluggable identity backend
upstream.  It is minimal, reversible, and isolated: only ``RNS.Identity`` is
replaced; nothing else in the RNS namespace is touched.

Configuration example (``~/.config/reticulum/config``)::

    [reticulum]
      identity_backend = pkcs11

    [pkcs11_identity]
      module       = /usr/lib/softhsm/libsofthsm2.so
      token_label  = MyToken
      sign_key_label = rns-sign
      enc_key_label  = rns-enc
      # pin = 1234   (omit and you will be prompted interactively)
      # pin_env = RETICULUM_PKCS11_PIN  (read PIN from this environment variable)

Environment variables:

    RETICULUM_CONFIGDIR — override the Reticulum config directory.

The patch is applied once when this module is imported.  Re-importing is safe.
"""

import os

from .exceptions import PKCS11KeyNotFoundError, PKCS11BackendError

_PATCH_APPLIED = False
_REQUIRED_CONFIG_KEYS = ("module", "token_label", "sign_key_label", "enc_key_label")


def _find_config_path() -> str | None:
    """Return the path to the Reticulum configuration file, or *None*."""
    candidates = []

    env_dir = os.environ.get("RETICULUM_CONFIGDIR")
    if env_dir:
        candidates.append(os.path.join(env_dir, "config"))

    home = os.path.expanduser("~")
    candidates += [
        "/etc/reticulum/config",
        os.path.join(home, ".config", "reticulum", "config"),
        os.path.join(home, ".reticulum", "config"),
    ]

    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _read_pkcs11_config() -> dict | None:
    """
    Parse the Reticulum config file and return the ``[pkcs11_identity]`` section
    as a plain dict, or *None* if PKCS#11 is not configured.
    """
    config_path = _find_config_path()
    if config_path is None:
        return None

    try:
        from RNS.vendor.configobj import ConfigObj
        config = ConfigObj(config_path)
    except Exception:
        return None

    reticulum_section = config.get("reticulum", {})
    if reticulum_section.get("identity_backend", "").strip().lower() != "pkcs11":
        return None

    pkcs11_section = config.get("pkcs11_identity", {})
    return dict(pkcs11_section)


def _resolve_pin(cfg: dict) -> str | None:
    """
    Resolve the PKCS#11 PIN from config or environment.

    Priority:
    1. ``pin`` value in ``[pkcs11_identity]`` config section.
    2. Environment variable named by ``pin_env`` in the config section.
    3. ``RETICULUM_PKCS11_PIN`` environment variable.
    4. *None* — the backend will prompt interactively.
    """
    if "pin" in cfg:
        return cfg["pin"]
    env_name = cfg.get("pin_env") or "RETICULUM_PKCS11_PIN"
    pin_from_env = os.environ.get(env_name)
    return pin_from_env  # may be None → interactive prompt


def _ensure_identity_keys(backend, cfg: dict) -> list[str]:
    """
    Ensure required identity keys exist on the selected token.

    Returns a list of key labels that were created.
    """
    created = []
    sign_label = cfg["sign_key_label"]
    enc_label = cfg["enc_key_label"]

    try:
        backend.get_public_key_bytes(key_label=sign_label)
    except PKCS11KeyNotFoundError:
        backend.generate_ed25519_keypair(label=sign_label)
        created.append(sign_label)

    try:
        backend.get_public_key_bytes(key_label=enc_label)
    except PKCS11KeyNotFoundError:
        backend.generate_x25519_keypair(label=enc_label)
        created.append(enc_label)

    return created


def apply_patch() -> bool:
    """
    Apply the PKCS#11 monkey-patch if the Reticulum configuration requests it.

    Returns *True* if the patch was applied, *False* if it was skipped (either
    because ``identity_backend`` is not ``pkcs11`` or because the patch has
    already been applied).

    This function is called automatically when the package is imported.
    """
    global _PATCH_APPLIED
    if _PATCH_APPLIED:
        return False

    cfg = _read_pkcs11_config()
    if cfg is None:
        return False

    # Validate required keys.
    for key in _REQUIRED_CONFIG_KEYS:
        if not cfg.get(key):
            import warnings
            warnings.warn(
                f"[reticulum_pkcs11_identity] Missing required config key "
                f"'{key}' in [pkcs11_identity] section; PKCS#11 patch skipped.",
                stacklevel=3,
            )
            return False

    pin = _resolve_pin(cfg)

    backend = None
    try:
        import RNS
        from .identity import make_hardware_identity_class

        backend = PKCS11Backend(
            module_path=cfg["module"],
            token_label=cfg["token_label"],
        )
        backend.open_session(
            pin=pin,
            prompt=f"PIN for PKCS#11 token '{cfg['token_label']}': ",
        )
        created_keys = _ensure_identity_keys(backend, cfg)

        HardwareIdentity = make_hardware_identity_class(
            backend=backend,
            sign_key_label=cfg["sign_key_label"],
            enc_key_label=cfg["enc_key_label"],
            sign_key_id=cfg.get("sign_key_id", "").encode() or None,
            enc_key_id=cfg.get("enc_key_id", "").encode() or None,
        )

        # ----------------------------------------------------------------
        # The patch: replace RNS.Identity with HardwareIdentity.
        # This is the only line that modifies the RNS namespace.
        # ----------------------------------------------------------------
        import RNS.Identity as _rns_identity_module
        RNS.Identity = HardwareIdentity
        _rns_identity_module.Identity = HardwareIdentity

        import atexit
        atexit.register(backend.close)

        _PATCH_APPLIED = True

        try:
            RNS.log(
                "[reticulum_pkcs11_identity] PKCS#11 identity backend active "
                f"(token: {cfg['token_label']})",
                RNS.LOG_VERBOSE,
            )
            if created_keys:
                created_str = ", ".join(created_keys)
                RNS.log(
                    "[reticulum_pkcs11_identity] Created missing PKCS#11 identity "
                    f"keys: {created_str}",
                    RNS.LOG_NOTICE,
                )
        except Exception:
            pass

        return True

    except (PKCS11BackendError, PKCS11KeyNotFoundError) as exc:
        import warnings
        warnings.warn(
            "[reticulum_pkcs11_identity] PKCS#11 key bootstrap failed: "
            f"{exc}",
            stacklevel=3,
        )
        return False
    except Exception as exc:
        import warnings
        warnings.warn(
            f"[reticulum_pkcs11_identity] Failed to apply PKCS#11 patch: {exc}",
            stacklevel=3,
        )
        return False
