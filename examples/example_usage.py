#!/usr/bin/env python3
# Reticulum PKCS#11 Identity - Example Usage
#
# This script demonstrates how to use reticulum_pkcs11_identity to:
#   1. Open a PKCS#11 token (SoftHSM2 is used here)
#   2. Generate identity key pairs on the token (first-time setup)
#   3. Create a HardwareIdentity
#   4. Use it for signing and decryption
#   5. Register it as a Reticulum destination
#
# To run this example you need:
#   - SoftHSM2 installed
#   - python-pkcs11 installed
#   - rns installed
#
# Quickstart with SoftHSM2:
#   softhsm2-util --init-token --slot 0 --label "MyToken" --pin 1234 --so-pin 12345678
#   python3 examples/example_usage.py

import os
import sys

# ── Locate the SoftHSM2 library ──────────────────────────────────────────────
SOFTHSM_CANDIDATES = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
]

MODULE_PATH = os.environ.get("PKCS11_MODULE")
if not MODULE_PATH:
    for path in SOFTHSM_CANDIDATES:
        if os.path.isfile(path):
            MODULE_PATH = path
            break

if not MODULE_PATH:
    print(
        "ERROR: Could not find libsofthsm2.so.\n"
        "Set PKCS11_MODULE=/path/to/your/pkcs11/module.so",
        file=sys.stderr,
    )
    sys.exit(1)

TOKEN_LABEL    = os.environ.get("PKCS11_TOKEN_LABEL", "MyToken")
TOKEN_PIN      = os.environ.get("PKCS11_PIN", "1234")
SIGN_KEY_LABEL = "rns-sign"
ENC_KEY_LABEL  = "rns-enc"

print(f"Using PKCS#11 module: {MODULE_PATH}")
print(f"Token label:          {TOKEN_LABEL}")

# ── 1. Open a PKCS#11 backend ────────────────────────────────────────────────
from reticulum_pkcs11_identity.backend import PKCS11Backend
from reticulum_pkcs11_identity.exceptions import PKCS11KeyNotFoundError

backend = PKCS11Backend(module_path=MODULE_PATH, token_label=TOKEN_LABEL)

# The PIN is requested exactly once here.  All subsequent operations reuse
# the same authenticated session — no re-prompting.
backend.open_session(pin=TOKEN_PIN)
print("PKCS#11 session opened.")

# ── 2. Generate key pairs (first-time setup) ─────────────────────────────────
print("\nChecking for existing keys on token …")

try:
    backend.get_public_key_bytes(key_label=SIGN_KEY_LABEL)
    print(f"  ✓ Ed25519 signing key '{SIGN_KEY_LABEL}' already present.")
except PKCS11KeyNotFoundError:
    print(f"  Generating Ed25519 signing key '{SIGN_KEY_LABEL}' …")
    backend.generate_ed25519_keypair(label=SIGN_KEY_LABEL)
    print("  ✓ Done.")

try:
    backend.get_public_key_bytes(key_label=ENC_KEY_LABEL)
    print(f"  ✓ X25519 encryption key '{ENC_KEY_LABEL}' already present.")
except PKCS11KeyNotFoundError:
    print(f"  Generating X25519 encryption key '{ENC_KEY_LABEL}' …")
    backend.generate_x25519_keypair(label=ENC_KEY_LABEL)
    print("  ✓ Done.")

# ── 3. Create a HardwareIdentity ─────────────────────────────────────────────
from reticulum_pkcs11_identity.identity import make_hardware_identity_class

HardwareIdentity = make_hardware_identity_class(
    backend=backend,
    sign_key_label=SIGN_KEY_LABEL,
    enc_key_label=ENC_KEY_LABEL,
)

identity = HardwareIdentity(create_keys=True)
print(f"\nHardware identity created.")
print(f"  Identity hash:  {identity.hexhash}")
print(f"  Public key:     {identity.get_public_key().hex()}")
print(f"  Private key in memory: {identity.get_private_key()}")

# ── 4. Sign a message ────────────────────────────────────────────────────────
print("\n── Signing ──")
message = b"Hello from a PKCS#11-backed Reticulum identity!"
signature = identity.sign(message)
print(f"  Message:   {message.decode()}")
print(f"  Signature: {signature.hex()[:32]}…  ({len(signature)} bytes)")

valid = identity.validate(signature, message)
print(f"  Verified:  {valid}")
assert valid, "Signature validation failed!"

# Confirm PIN is not re-prompted: sign again without any new credentials.
for i in range(3):
    sig = identity.sign(f"message {i}".encode())
    assert identity.validate(sig, f"message {i}".encode())
print("  ✓ Signed 3 more messages — PIN was NOT re-prompted.")

# ── 5. Encrypt and decrypt ───────────────────────────────────────────────────
print("\n── Encryption / Decryption ──")
plaintext  = b"Confidential payload for the hardware identity."
ciphertext = identity.encrypt(plaintext)
print(f"  Plaintext:  {plaintext.decode()}")
print(f"  Ciphertext: {ciphertext.hex()[:32]}…  ({len(ciphertext)} bytes)")

recovered = identity.decrypt(ciphertext)
print(f"  Recovered:  {recovered.decode()}")
assert recovered == plaintext, "Decryption produced wrong result!"
print("  ✓ Plaintext recovered correctly.")

# ── 6. (Optional) Register with Reticulum ────────────────────────────────────
print("\n── Reticulum integration ──")
try:
    import RNS

    config_dir = "/tmp/rns-pkcs11-example"
    os.makedirs(config_dir, exist_ok=True)

    # Optionally apply the global monkey-patch so RNS.Identity is replaced.
    # In production this happens automatically when the package is imported
    # if identity_backend = pkcs11 is in the Reticulum config.
    original_identity = RNS.Identity
    RNS.Identity = HardwareIdentity

    try:
        reticulum = RNS.Reticulum(configdir=config_dir)
        destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            "example_pkcs11",
            "demo",
        )
        print(f"  Reticulum destination: {RNS.prettyhexrep(destination.hash)}")
        print("  ✓ Hardware identity successfully registered with Reticulum.")
    finally:
        RNS.Transport.exit_handler()
        RNS.Identity = original_identity

except ImportError:
    print("  Reticulum (rns) is not installed; skipping RNS integration demo.")

# ── Cleanup ───────────────────────────────────────────────────────────────────
backend.close()
print("\nPKCS#11 session closed.  Done.")
