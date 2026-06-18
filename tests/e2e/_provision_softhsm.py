"""Out-of-process SoftHSM2 provisioning helper for the two-instance e2e test.

This module is **not** a test (the leading underscore keeps pytest from
collecting it). It exists because ``python-pkcs11`` calls ``C_Initialize``
exactly **once per process** and SoftHSM2 binds the token directory it sees in
``SOFTHSM2_CONF`` at that moment. If the parent pytest process opened a backend
against the e2e token, that one-time initialisation would poison every later
test in the same process (they would no longer find their own ``RNS-Test-Token``
— a cascade of "token is not present" errors).

So the parent never loads the PKCS#11 module itself. Instead it launches this
script as a separate process, which gets its **own** ``C_Initialize``, generates
the two node key pairs on the e2e token, reads the public keys back, and prints
a single JSON object to stdout describing the result.

Usage::

    python _provision_softhsm.py <config.json>

``config.json`` keys::

    module        absolute path to the SoftHSM2 PKCS#11 module
    softhsm2_conf absolute path to the SoftHSM2 config to use
    token_label   label of the (already init-token'd) token
    pin           user PIN
    nodes         list of node names, e.g. ["nodeA", "nodeB"]

stdout (a single JSON object, last non-empty line)::

    {"status": "ok", "pubkeys": {"nodeA": {"enc": "<hex>", "sign": "<hex>"}, ...},
     "key_attrs": {"nodeA": {"enc": {"token": true, "sensitive": true,
                                     "extractable": false, ...}, "sign": {...}}}}
    {"status": "unsupported", "reason": "..."}   # EdDSA-less SoftHSM2 -> skip
    {"status": "error", "reason": "..."}         # anything else -> fail
"""

from __future__ import annotations

import json
import os
import sys
import traceback


def main() -> int:
    cfg = json.loads(open(sys.argv[1]).read())

    os.environ["SOFTHSM2_CONF"] = cfg["softhsm2_conf"]

    try:
        from reticulum_pkcs11_identity.backend import PKCS11Backend
    except Exception as exc:  # pragma: no cover - import/env specific
        print(json.dumps({"status": "error", "reason": f"import failed: {exc}"}))
        return 1

    backend = PKCS11Backend(
        module_path=cfg["module"], token_label=cfg["token_label"]
    )
    try:
        backend.open_session(pin=cfg["pin"])
    except Exception as exc:  # pragma: no cover - env specific
        print(json.dumps({"status": "error", "reason": f"open_session failed: {exc}"}))
        return 1

    pubkeys: dict[str, dict[str, str]] = {}
    key_attrs: dict[str, dict[str, dict]] = {}
    try:
        from pkcs11 import Attribute

        def _priv_attrs(priv_obj) -> dict:
            """Read the security-relevant attributes off a private key object.

            Proves the key lives on the token (CKA_TOKEN) and cannot be exported
            to a filesystem (CKA_SENSITIVE / not CKA_EXTRACTABLE). SoftHSM2 may
            refuse some attribute reads; record ``None`` in that case.
            """
            out = {}
            for name, attr in (
                ("token", Attribute.TOKEN),
                ("private", Attribute.PRIVATE),
                ("sensitive", Attribute.SENSITIVE),
                ("extractable", Attribute.EXTRACTABLE),
            ):
                try:
                    out[name] = bool(priv_obj[attr])
                except Exception:
                    out[name] = None
            return out

        for node in cfg["nodes"]:
            try:
                _, sign_priv = backend.generate_ed25519_keypair(f"{node}-sign")
                _, enc_priv = backend.generate_x25519_keypair(f"{node}-enc")
            except Exception as exc:  # MechanismInvalid on EdDSA-less SoftHSM2
                print(json.dumps({
                    "status": "unsupported",
                    "reason": f"{type(exc).__name__}: {exc}",
                }))
                return 0
            sign_pub = backend.get_public_key_bytes(key_label=f"{node}-sign")
            enc_pub = backend.get_public_key_bytes(key_label=f"{node}-enc")
            pubkeys[node] = {"enc": enc_pub.hex(), "sign": sign_pub.hex()}
            key_attrs[node] = {
                "sign": _priv_attrs(sign_priv),
                "enc": _priv_attrs(enc_priv),
            }
    except Exception as exc:  # pragma: no cover - env specific
        print(json.dumps({"status": "error", "reason": f"{type(exc).__name__}: {exc}"}))
        return 1
    finally:
        try:
            backend.close()
        except Exception:
            pass

    print(json.dumps({"status": "ok", "pubkeys": pubkeys, "key_attrs": key_attrs}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # pragma: no cover - last-resort diagnostics
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"status": "error", "reason": "unhandled exception"}))
        sys.exit(1)
