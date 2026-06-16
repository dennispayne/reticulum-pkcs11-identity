# reticulum-pkcs11-identity

PKCS#11-backed **LXMF user identity** support for Reticulum.

## Scope

This project now targets one thing only: provisioning and using a hardware-backed **user/LXMF identity**.  
It no longer performs global `RNS.Identity` monkey-patching and does not target node identity replacement.

## Core architecture

- `backend.py` – PKCS#11 session lifecycle + sign/ECDH primitives.
- `identity.py` – explicit hardware identity class factory.
- `lxmf.py` – LXMF-only bootstrap/config helpers.
- `discovery.py` – provider/token inventory utilities.

## Installation

```bash
pip install reticulum-pkcs11-identity
```

## LXMF config section

Add this to your Reticulum config file (`~/.config/reticulum/config`):

```ini
[lxmf_pkcs11_identity]
module = /usr/lib/softhsm/libsofthsm2.so
token_label = MyToken
sign_key_label = lxmf-sign
enc_key_label = lxmf-enc
# pin = 1234
# pin_env = LXMF_PKCS11_PIN
```

## Programmatic usage

```python
from reticulum_pkcs11_identity import (
    load_lxmf_hardware_identity_config,
    create_lxmf_hardware_identity,
)

cfg = load_lxmf_hardware_identity_config()
if cfg is None:
    raise RuntimeError("Missing [lxmf_pkcs11_identity] config")

handle = create_lxmf_hardware_identity(cfg, ensure_keys=True)
lxmf_identity = handle.identity

# Use lxmf_identity as your LXMF user identity in app code.
# ...

handle.close()
```

## Token discovery

```python
from reticulum_pkcs11_identity import enumerate_token_inventory, format_token_inventory
print(format_token_inventory(enumerate_token_inventory()))
```

Discovery checks readiness against default LXMF labels (`lxmf-sign` / `lxmf-enc`).

## Testing

```bash
# Linux/macOS
bash scripts/bootstrap_test_env.sh
.venv/bin/python -m pytest tests -v

# Windows PowerShell
powershell -File scripts\bootstrap_test_env.ps1
.venv\Scripts\python.exe -m pytest tests -v
```

SoftHSM-backed tests auto-skip if SoftHSM2 is unavailable.
