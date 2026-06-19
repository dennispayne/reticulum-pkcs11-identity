"""Deterministic reproduction of the two-instance e2e flakiness.

The flaky symptom is that the *softhsm* e2e server child exits with -11
(SIGSEGV) or -9 (SIGKILL after a native hang), always right after the link's
``remote identified`` callback fires. That is the exact moment a SECOND thread
starts touching the token: the RNS main loop keeps ``announce()``-signing while
an RNS packet-callback thread starts ``decrypt()``-ing the inbound app packets.

Root-cause hypothesis this script is designed to confirm/deny:

    ``identity.sign()`` / ``identity.decrypt()`` both call
    ``_check_token_state()`` -> ``TokenMonitor.detect_changes()`` ->
    ``lib.get_slots(token_present=True)`` (native ``C_GetSlotList`` /
    ``C_GetTokenInfo``) under the monitor's OWN lock, while the actual crypto
    runs under the *backend's* (different) lock. So {crypto op} x {slot
    enumeration} can run concurrently against one SoftHSM2 module with NO shared
    mutex -> intermittent native corruption (SIGSEGV) or internal deadlock.

This harness removes all network latency and hammers the same two API calls
(``sign`` on one thread, ``decrypt`` on another) so the race window is hit in
seconds instead of ~1-in-5 full e2e runs. ``faulthandler`` is armed so a crash
or a hang both dump every thread's stack.

Run it directly (or via the "Debug: PKCS#11 thread-race repro" launch config):

    python -m tests.e2e._stress_token_threads          # default: 4000 iters
    STRESS_ITERS=20000 STRESS_SECONDS=30 python -m tests.e2e._stress_token_threads

Exit code 0 = survived (no crash/hang); non-zero or signal = reproduced.
"""

from __future__ import annotations

import faulthandler
import os
import shutil
import sys
import tempfile
import threading
import time

# Arm crash/hang diagnostics: any fatal signal dumps all thread stacks, and if
# the process is still alive after STRESS_SECONDS it is force-dumped and killed
# (a native deadlock otherwise produces no output at all).
faulthandler.enable()
_WATCHDOG_SECONDS = float(os.environ.get("STRESS_SECONDS", "30"))
faulthandler.dump_traceback_later(_WATCHDOG_SECONDS, exit=True)

# Make the repo + conftest helpers importable when run as a plain script.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.conftest import _find_softhsm_module, _find_softhsm2_util, _softhsm2_util


def _provision_token():
    """Init a throwaway SoftHSM2 token with one Ed25519 + one X25519 key pair."""
    module = _find_softhsm_module()
    if module is None or _find_softhsm2_util() is None:
        print("SKIP: no EdDSA-capable SoftHSM2 available", flush=True)
        raise SystemExit(0)

    tmp = tempfile.mkdtemp(prefix="pkcs11-race-")
    token_dir = os.path.join(tmp, "tokens")
    os.makedirs(token_dir)
    conf = os.path.join(tmp, "softhsm2.conf")
    with open(conf, "w") as fh:
        fh.write(
            f"directories.tokendir = {token_dir}\n"
            "objectstore.backend = file\n"
            "log.level = ERROR\n"
            "slots.removable = false\n"
        )
    os.environ["SOFTHSM2_CONF"] = conf

    label, pin, sopin = "RACE", "1234", "12345678"
    res = _softhsm2_util(
        "--init-token", "--slot", "0",
        "--label", label, "--pin", pin, "--so-pin", sopin,
        env=dict(os.environ),
    )
    if res.returncode != 0:
        print(f"SKIP: init-token failed:\n{res.stdout}\n{res.stderr}", flush=True)
        raise SystemExit(0)
    return module, conf, label, pin, tmp


def main() -> int:
    module, conf, label, pin, tmp = _provision_token()

    import RNS  # noqa: F401  (identity subclasses RNS.Identity)
    from reticulum_pkcs11_identity.backend import PKCS11Backend
    from reticulum_pkcs11_identity.identity import make_lxmf_identity_class

    backend = PKCS11Backend(module_path=module, token_label=label)
    backend.open_session(pin=pin)
    try:
        backend.generate_ed25519_keypair("race-sign")
    except Exception as exc:  # EdDSA-less SoftHSM2
        print(f"SKIP: keygen unsupported: {type(exc).__name__}: {exc}", flush=True)
        return 0
    backend.generate_x25519_keypair("race-enc")

    identity_cls = make_lxmf_identity_class(
        backend=backend, sign_key_label="race-sign", enc_key_label="race-enc",
    )
    identity = identity_cls(create_keys=True)

    # A real Reticulum ciphertext token addressed to this identity. Decrypting
    # it routes the X25519 ECDH through the token (the path the e2e exercises).
    ciphertext = identity.encrypt(b"meet me where the loopback never sleeps")

    iters = int(os.environ.get("STRESS_ITERS", "4000"))
    stop = threading.Event()
    counters = {"sign": 0, "decrypt": 0}
    errors: list[str] = []

    def sign_loop():
        # Mirrors the server's announce loop: sign on the main-ish thread.
        for _ in range(iters):
            if stop.is_set():
                return
            try:
                identity.sign(b"announce-proof-payload")
                counters["sign"] += 1
            except Exception as exc:  # noqa: BLE001 - record, keep racing
                errors.append(f"sign: {type(exc).__name__}: {exc}")
                return

    def decrypt_loop():
        # Mirrors the RNS packet-callback thread: decrypt inbound app traffic.
        for _ in range(iters):
            if stop.is_set():
                return
            try:
                identity.decrypt(ciphertext)
                counters["decrypt"] += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"decrypt: {type(exc).__name__}: {exc}")
                return

    print(
        f"[race] hammering sign||decrypt for up to {iters} iters / "
        f"{_WATCHDOG_SECONDS:.0f}s (pid={os.getpid()})",
        flush=True,
    )
    t0 = time.time()
    threads = [
        threading.Thread(target=sign_loop, name="sign-loop"),
        threading.Thread(target=decrypt_loop, name="decrypt-loop"),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop.set()
    faulthandler.cancel_dump_traceback_later()

    dt = time.time() - t0
    print(
        f"[race] SURVIVED: sign={counters['sign']} decrypt={counters['decrypt']} "
        f"in {dt:.1f}s; errors={errors[:3]}",
        flush=True,
    )
    backend.close()
    shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
