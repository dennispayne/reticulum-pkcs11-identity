"""Two-instance, OS-local Reticulum end-to-end test.

This exercises the scenario the project cares about: a Reticulum application
that, on first launch, creates an identity which is then used to talk to a
*second*, independent Reticulum instance running on the same machine — without
touching the real network and without disturbing any Reticulum instance the
developer already has running.

Design (see ``_rns_peer.py`` for the per-peer logic):

  * Two **separate processes** (Reticulum keeps Transport/destination tables in
    process-global state, so two instances cannot share one interpreter).
  * Connected over **kernel loopback TCP** (``127.0.0.1``) — an OS-local bearer,
    no physical/virtual NIC involved.
  * Each instance gets an **isolated temp configdir**, ``share_instance = No``,
    and unique control ports, so they are independent of any pre-existing
    Reticulum on the box.

Two identity providers are parametrized:

  ``software`` — plain ``RNS.Identity``. Always runs; validates the loopback
                 orchestration end-to-end (and is the only variant that works
                 on native Windows, where no EdDSA-capable SoftHSM2 exists).
  ``softhsm``  — both identities are **token-backed** PKCS#11 identities whose
                 sign/decrypt operations route through SoftHSM2. Skips unless a
                 SoftHSM2 that actually supports Ed25519/X25519 is installed
                 (true on Linux 2.6.1; SoftHSM2 never advertises the mechanism
                 in ``C_GetMechanismList``, so capability is probed by *trying*
                 a keygen). A single token holds both nodes' key pairs, proving
                 two identities can be served from one token simultaneously.

The client proves its identity to the server over the link via
``link.identify()`` (which *signs* with the identity key — token-routed in the
softhsm variant). The assertions confirm the bytes round-tripped **and** that
the identity hash the server captured over the wire equals the client's own
identity hash — i.e. the right (token-backed) key signed the link proof.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

import pytest

from tests.conftest import _find_softhsm2_util, _find_softhsm_module, _softhsm2_util

try:
    import RNS  # noqa: F401

    HAS_RNS = True
except ImportError:
    HAS_RNS = False

PEER_SCRIPT = os.path.join(os.path.dirname(__file__), "_rns_peer.py")
APP_NAME = "pkcs11e2e"
ASPECTS = ["echo"]
PAYLOAD = b"hardware-identity-says-hello"
PEER_TIMEOUT = 60
READY_TIMEOUT = 25
JOIN_TIMEOUT = 90
LOGLEVEL = int(os.environ.get("RNS_E2E_LOGLEVEL", "3"))


def _free_port() -> int:
    """Grab an ephemeral loopback port (briefly) to reuse for a child."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _provision_softhsm_two_identities(tmp_path) -> dict:
    """Create a fresh SoftHSM2 token holding two Ed25519+X25519 key pairs.

    Returns a dict of connection parameters, or calls ``pytest.skip`` if no
    EdDSA-capable SoftHSM2 is available (e.g. native Windows).
    """
    module = _find_softhsm_module()
    if module is None or _find_softhsm2_util() is None:
        pytest.skip(
            "SoftHSM2 not installed; the token-backed two-instance e2e needs an "
            "EdDSA-capable SoftHSM2 (Linux 2.6.1). Run this variant under WSL/Linux."
        )

    token_dir = tmp_path / "softhsm_tokens"
    token_dir.mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(
        f"directories.tokendir = {token_dir}\n"
        "objectstore.backend = file\n"
        "log.level = ERROR\n"
        "slots.removable = false\n"
    )

    env = dict(os.environ)
    env["SOFTHSM2_CONF"] = str(conf)
    label, pin, sopin = "RNS-E2E", "1234", "12345678"

    result = _softhsm2_util(
        "--init-token", "--slot", "0",
        "--label", label, "--pin", pin, "--so-pin", sopin,
        env=env,
    )
    assert result.returncode == 0, (
        f"softhsm2-util --init-token failed:\n{result.stdout}\n{result.stderr}"
    )

    # The backend reads SOFTHSM2_CONF at module C_Initialize time.
    os.environ["SOFTHSM2_CONF"] = str(conf)
    from reticulum_pkcs11_identity.backend import PKCS11Backend

    backend = PKCS11Backend(module_path=module, token_label=label)
    backend.open_session(pin=pin)
    try:
        for node in ("nodeA", "nodeB"):
            try:
                backend.generate_ed25519_keypair(f"{node}-sign")
                backend.generate_x25519_keypair(f"{node}-enc")
            except Exception as exc:  # MechanismInvalid on EdDSA-less SoftHSM2
                pytest.skip(
                    f"Installed SoftHSM2 cannot generate Curve25519 keys "
                    f"({type(exc).__name__}: {exc}). Use Linux SoftHSM2 2.6.1."
                )
    finally:
        backend.close()

    return {
        "provider": "softhsm",
        "module": module,
        "softhsm2_conf": str(conf),
        "token_label": label,
        "pin": pin,
    }


def _spawn_peer(config: dict, tmp_path, tag: str) -> subprocess.Popen:
    cfg_path = tmp_path / f"{tag}_config.json"
    cfg_path.write_text(json.dumps(config))
    child_env = dict(os.environ)
    # Make the repo importable for the child even if not pip-installed.
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    child_env["PYTHONPATH"] = repo_root + os.pathsep + child_env.get("PYTHONPATH", "")
    if config["identity"].get("softhsm2_conf"):
        child_env["SOFTHSM2_CONF"] = config["identity"]["softhsm2_conf"]
    # Redirect child output to files rather than pipes. A peer can emit a fair
    # amount of RNS logging on stderr, and the parent only drains it *after*
    # the exchange completes; with pipes that would deadlock once the OS pipe
    # buffer (~64 KB on Windows) fills and the child blocks on write. Files
    # have no such limit.
    out_fh = open(tmp_path / f"{tag}_stdout.log", "w")
    err_fh = open(tmp_path / f"{tag}_stderr.log", "w")
    proc = subprocess.Popen(
        [sys.executable, PEER_SCRIPT, str(cfg_path)],
        stdout=out_fh,
        stderr=err_fh,
        env=child_env,
        text=True,
    )
    # Stash handles + paths so _drain can close them and read the output back.
    proc._e2e_capture = (out_fh, err_fh,
                         tmp_path / f"{tag}_stdout.log",
                         tmp_path / f"{tag}_stderr.log")
    return proc


def _drain(proc: subprocess.Popen, timeout: int) -> tuple[int, str, str]:
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    out_fh, err_fh, out_path, err_path = proc._e2e_capture
    out_fh.close()
    err_fh.close()
    out = out_path.read_text(errors="replace")
    err = err_path.read_text(errors="replace")
    return proc.returncode, out, err


@pytest.mark.skipif(not HAS_RNS, reason="RNS not installed")
@pytest.mark.integration
@pytest.mark.parametrize("provider", ["software", "softhsm"])
def test_two_instance_loopback_e2e(provider, tmp_path):
    """First-launch identity creation, then a real link exchange between two
    independent local Reticulum instances over loopback TCP."""
    if provider == "software":
        id_a = {"provider": "software"}
        id_b = {"provider": "software"}
    else:
        tok = _provision_softhsm_two_identities(tmp_path)
        id_a = {**tok, "sign_label": "nodeA-sign", "enc_label": "nodeA-enc"}
        id_b = {**tok, "sign_label": "nodeB-sign", "enc_label": "nodeB-enc"}

    link_port = _free_port()
    ready_file = tmp_path / "b_ready.txt"
    b_result_file = tmp_path / "b_result.json"
    a_result_file = tmp_path / "a_result.json"

    server_cfg = {
        "role": "server",
        "configdir": str(tmp_path / "B_config"),
        "interface": {
            "type": "TCPServerInterface",
            "listen_ip": "127.0.0.1",
            "listen_port": link_port,
        },
        "shared_instance_port": _free_port(),
        "instance_control_port": _free_port(),
        "loglevel": LOGLEVEL,
        "identity": id_b,
        "app_name": APP_NAME,
        "aspects": ASPECTS,
        "payload": PAYLOAD.hex(),
        "ready_file": str(ready_file),
        "result_file": str(b_result_file),
        "timeout": PEER_TIMEOUT,
    }

    server = _spawn_peer(server_cfg, tmp_path, "B")

    # Wait for the server to publish its destination hash.
    dest_hash = None
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        if ready_file.exists() and ready_file.read_text().strip():
            dest_hash = ready_file.read_text().strip()
            break
        if server.poll() is not None:  # server died early
            break
        time.sleep(0.2)

    if dest_hash is None:
        code, out, err = _drain(server, timeout=5)
        pytest.fail(
            f"server never became ready (exit={code}).\nSTDOUT:\n{out}\nSTDERR:\n{err}"
        )

    client_cfg = {
        "role": "client",
        "configdir": str(tmp_path / "A_config"),
        "interface": {
            "type": "TCPClientInterface",
            "target_host": "127.0.0.1",
            "target_port": link_port,
        },
        "shared_instance_port": _free_port(),
        "instance_control_port": _free_port(),
        "loglevel": LOGLEVEL,
        "identity": id_a,
        "app_name": APP_NAME,
        "aspects": ASPECTS,
        "payload": PAYLOAD.hex(),
        "peer_dest_hash": dest_hash,
        "result_file": str(a_result_file),
        "timeout": PEER_TIMEOUT,
    }

    client = _spawn_peer(client_cfg, tmp_path, "A")

    a_code, a_out, a_err = _drain(client, timeout=JOIN_TIMEOUT)
    b_code, b_out, b_err = _drain(server, timeout=JOIN_TIMEOUT)

    diag = (
        f"\n--- server exit={b_code} ---\nSTDOUT:\n{b_out}\nSTDERR:\n{b_err}"
        f"\n--- client exit={a_code} ---\nSTDOUT:\n{a_out}\nSTDERR:\n{a_err}"
    )

    assert a_result_file.exists(), f"client wrote no result.{diag}"
    assert b_result_file.exists(), f"server wrote no result.{diag}"
    a_res = json.loads(a_result_file.read_text())
    b_res = json.loads(b_result_file.read_text())

    assert b_res.get("ok"), f"server did not complete exchange: {b_res}{diag}"
    assert a_res.get("ok"), f"client did not complete exchange: {a_res}{diag}"
    assert a_res.get("echo_received"), f"client got no echo: {a_res}{diag}"
    assert b_res.get("received_payload") == PAYLOAD.hex(), (
        f"payload mismatch: {b_res}{diag}"
    )
    # The identity the server captured over the link must be the client's
    # actual identity — proving the (token-backed) key signed the link proof.
    assert a_res.get("identity_hash") == b_res.get("remote_identity_hash"), (
        f"identity binding mismatch: client={a_res.get('identity_hash')} "
        f"server-saw={b_res.get('remote_identity_hash')}{diag}"
    )
    # The two identities must be distinct (two independent nodes).
    assert a_res.get("identity_hash") != b_res.get("identity_hash"), (
        f"both peers reported the same identity hash{diag}"
    )
