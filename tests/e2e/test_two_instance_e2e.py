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
PROVISION_SCRIPT = os.path.join(os.path.dirname(__file__), "_provision_softhsm.py")
APP_NAME = "pkcs11e2e"
ASPECTS = ["echo"]
PAYLOAD = b"hardware-identity-says-hello"
# Real application-layer messages exchanged on top of the link. APP_MESSAGE is
# encrypted to the recipient (server) and must be readable; DECOY_MESSAGE is
# encrypted to the sender's own identity and must be UNreadable by the server.
APP_MESSAGE = b"meet me where the loopback never sleeps -- from A"
DECOY_MESSAGE = b"for A's eyes only; the server must never read this"
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


def _rns_identity_hash(enc_pub: bytes, sign_pub: bytes) -> str:
    """Derive the RNS identity hash from raw public keys, independently of the
    token code path.

    A token-backed peer sets ``pub_bytes = enc_pub`` and ``sig_pub_bytes =
    sign_pub`` and lets RNS compute the hash over ``enc_pub + sign_pub``. We
    reproduce that here so the parent can assert the peer reported *this* exact
    hash — proving the peer actually used the token keys and did not silently
    fall back to a random software identity.
    """
    import RNS

    probe = RNS.Identity(create_keys=False)
    probe.load_public_key(enc_pub + sign_pub)
    return probe.hash.hex()


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

    # Provision the node key pairs and read their public keys back in a SEPARATE
    # PROCESS. python-pkcs11 calls C_Initialize once per process and SoftHSM2
    # binds the tokendir from SOFTHSM2_CONF at that moment; if the parent pytest
    # process opened a backend against this e2e token, every later test in the
    # same process would stop finding its own RNS-Test-Token (a cascade of
    # "token is not present" errors). So the parent never loads the module — a
    # child does, gets its own C_Initialize, and hands back the public keys.
    prov_cfg = tmp_path / "provision.json"
    prov_cfg.write_text(json.dumps({
        "module": module,
        "softhsm2_conf": str(conf),
        "token_label": label,
        "pin": pin,
        "nodes": ["nodeA", "nodeB"],
    }))
    child_env = dict(os.environ)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    child_env["PYTHONPATH"] = repo_root + os.pathsep + child_env.get("PYTHONPATH", "")
    child_env["SOFTHSM2_CONF"] = str(conf)
    proc = subprocess.run(
        [sys.executable, PROVISION_SCRIPT, str(prov_cfg)],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=PEER_TIMEOUT,
    )
    payload = ""
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            payload = line.strip()
    try:
        prov = json.loads(payload) if payload else {}
    except json.JSONDecodeError:
        prov = {}
    if prov.get("status") == "unsupported":
        pytest.skip(
            f"Installed SoftHSM2 cannot generate Curve25519 keys "
            f"({prov.get('reason')}). Use Linux SoftHSM2 2.6.1."
        )
    assert prov.get("status") == "ok", (
        "SoftHSM2 provisioning subprocess failed.\n"
        f"exit={proc.returncode}\nstatus={prov.get('status')} "
        f"reason={prov.get('reason')}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )

    pubkeys: dict[str, tuple[bytes, bytes]] = {}
    for node in ("nodeA", "nodeB"):
        node_keys = prov["pubkeys"][node]
        pubkeys[node] = (
            bytes.fromhex(node_keys["enc"]),
            bytes.fromhex(node_keys["sign"]),
        )

    # --- Environment assurances: fail loudly (not skip) if the token did not
    # end up in the state the test depends on, so a later "pass" can be trusted.
    a_enc, a_sign = pubkeys["nodeA"]
    b_enc, b_sign = pubkeys["nodeB"]
    for who, (enc, sig) in (("nodeA", pubkeys["nodeA"]), ("nodeB", pubkeys["nodeB"])):
        assert len(enc) == 32, f"{who} X25519 pubkey wrong size: {len(enc)}"
        assert len(sig) == 32, f"{who} Ed25519 pubkey wrong size: {len(sig)}"
    assert a_sign != b_sign, "nodeA and nodeB share a signing key — not isolated"
    assert a_enc != b_enc, "nodeA and nodeB share an encryption key — not isolated"

    # --- Token-residency proof ------------------------------------------
    # The private keys our module generated must be token objects that cannot
    # be exported to a filesystem. This is what makes the resulting identity a
    # *PKCS#11* identity rather than a software/file one. The X25519 (enc) key
    # is the one that decrypts user app traffic, so it matters most.
    attrs = prov.get("key_attrs", {})
    for node in ("nodeA", "nodeB"):
        enc_attrs = attrs.get(node, {}).get("enc", {})
        sign_attrs = attrs.get(node, {}).get("sign", {})
        assert enc_attrs.get("token") is True, (
            f"{node} X25519 (decryption) key is not a token object: {enc_attrs}"
        )
        assert enc_attrs.get("extractable") is not True, (
            f"{node} X25519 key is EXTRACTABLE — it could be copied off the "
            f"token to disk: {enc_attrs}"
        )
        assert sign_attrs.get("token") is True, (
            f"{node} Ed25519 (signing) key is not a token object: {sign_attrs}"
        )
        assert sign_attrs.get("extractable") is not True, (
            f"{node} Ed25519 key is EXTRACTABLE: {sign_attrs}"
        )

    expected_hashes = {
        "nodeA": _rns_identity_hash(a_enc, a_sign),
        "nodeB": _rns_identity_hash(b_enc, b_sign),
    }
    assert expected_hashes["nodeA"] != expected_hashes["nodeB"], (
        "derived identity hashes collided — token keys not distinct"
    )

    return {
        "provider": "softhsm",
        "module": module,
        "softhsm2_conf": str(conf),
        "token_label": label,
        "pin": pin,
        "expected_hashes": expected_hashes,
        "key_attrs": attrs,
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


def _indent(text: str, prefix: str = "    ") -> str:
    """Indent every line of ``text`` (and tidy a blank/whitespace-only block)."""
    text = (text or "").rstrip()
    if not text:
        return prefix + "(none)"
    return "\n".join(prefix + line for line in text.splitlines())


def _emit(title: str, lines: list[str], cap=None) -> None:
    """Print a titled, framed report block.

    When ``cap`` (the ``capsys`` fixture) is supplied the block is written with
    capturing temporarily disabled, so it ALWAYS reaches the terminal — on a
    passing run too, without needing ``-s``. Keep these blocks short: report the
    verdict, not every internal detail.
    """
    width = 78

    def _write() -> None:
        print("\n" + "=" * width)
        print(title)
        print("-" * width)
        for line in lines:
            print(line)
        print("=" * width, flush=True)

    if cap is not None:
        with cap.disabled():
            _write()
    else:
        _write()


@pytest.mark.skipif(not HAS_RNS, reason="RNS not installed")
@pytest.mark.integration
@pytest.mark.parametrize(
    "provider",
    ["software", "softhsm"],
    ids=["plain-RNS-software-identity", "SoftHSM2-token-backed-identity"],
)
def test_two_instance_loopback_e2e(provider, tmp_path, capsys):
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
        _emit(
            f"E2E FAILED — server never became ready (provider={provider!r})",
            [
                f"server exit code: {code}",
                "server STDOUT:",
                _indent(out),
                "server STDERR:",
                _indent(err),
            ],
            cap=capsys,
        )
        pytest.fail(
            f"server never became ready (exit={code}).\nSTDOUT:\n{out}\nSTDERR:\n{err}"
        )

    print(f"[e2e] server ready; destination hash = {dest_hash}", flush=True)

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
        "app_message": APP_MESSAGE.hex(),
        "decoy_message": DECOY_MESSAGE.hex(),
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

    a_res = json.loads(a_result_file.read_text()) if a_result_file.exists() else {}
    b_res = json.loads(b_result_file.read_text()) if b_result_file.exists() else {}

    # --- Behaviour assertions -------------------------------------------
    assert a_result_file.exists(), f"client wrote no result.{diag}"
    assert b_result_file.exists(), f"server wrote no result.{diag}"

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

    # --- Application-layer messaging ------------------------------------
    # User A encrypted a message to user B's identity; B must have decrypted
    # and read it. This is genuine user-app traffic, end-to-end encrypted a
    # layer above the link's own transport encryption.
    assert b_res.get("app_message_decrypted") == APP_MESSAGE.hex(), (
        f"server failed to decrypt user A's application message: "
        f"got {b_res.get('app_message_decrypted')}, "
        f"expected {APP_MESSAGE.hex()}{diag}"
    )
    # The decoy was addressed to A's own identity; B is the wrong recipient
    # and must be UNABLE to read it (negative/expected-failure case).
    assert b_res.get("decoy_decryptable") is False, (
        f"server decrypted a message it was not the recipient of "
        f"(decoy addressed to the client): {b_res.get('decoy_recovered')}{diag}"
    )
    assert b_res.get("decoy_recovered") is None, (
        f"server recovered decoy plaintext it must not have: "
        f"{b_res.get('decoy_recovered')}{diag}"
    )

    # --- Identity provenance: prove WE made the identity ----------------
    # The user traffic above is only as trustworthy as the identity that
    # secured it. Prove each peer ran an identity object PRODUCED BY THIS
    # PACKAGE and holding no private key in memory (softhsm), versus a stock
    # in-memory RNS identity (software).
    if provider == "softhsm":
        for who, res in (("client", a_res), ("server", b_res)):
            assert (res.get("identity_module") or "").startswith(
                "reticulum_pkcs11_identity"
            ), (
                f"{who} identity was NOT produced by this package "
                f"(module={res.get('identity_module')}); it cannot be a "
                f"PKCS#11-backed identity.{diag}"
            )
            assert res.get("has_in_memory_private_key") is False, (
                f"{who} identity holds a private key in memory — that is a "
                f"software/filesystem identity, not a token one.{diag}"
            )
    else:
        for who, res in (("client", a_res), ("server", b_res)):
            assert res.get("has_in_memory_private_key") is True, (
                f"{who} software identity unexpectedly has no in-memory key.{diag}"
            )

    # --- Believability assurances ---------------------------------------
    # Guard against a "green" result that doesn't actually exercise what the
    # variant claims to exercise.
    if provider == "softhsm":
        # 1. Both peers must be genuinely token-backed, not a silent software
        #    fallback (which would still pass the behaviour checks above).
        assert a_res.get("is_hardware") is True, (
            f"client claims softhsm but identity is not token-backed: {a_res}{diag}"
        )
        assert b_res.get("is_hardware") is True, (
            f"server claims softhsm but identity is not token-backed: {b_res}{diag}"
        )
        assert a_res.get("identity_provider") == "softhsm"
        assert b_res.get("identity_provider") == "softhsm"

        # 2. Each peer's reported identity must match the hash we independently
        #    derived from the public keys *read off the token*. This proves the
        #    keys that signed the link proof are the token keys we provisioned,
        #    not random ones generated in-process.
        expected = tok["expected_hashes"]
        assert a_res.get("identity_hash") == expected["nodeA"], (
            f"client identity {a_res.get('identity_hash')} != token-derived "
            f"nodeA {expected['nodeA']}; token keys were NOT the ones used.{diag}"
        )
        assert b_res.get("identity_hash") == expected["nodeB"], (
            f"server identity {b_res.get('identity_hash')} != token-derived "
            f"nodeB {expected['nodeB']}; token keys were NOT the ones used.{diag}"
        )
    else:
        # Software variant: the public key the peer used must be the 64-byte
        # RNS key material, and the link-bound identity hash must be consistent
        # with that key material — i.e. the exchange really carried this key.
        for who, res in (("client", a_res), ("server", b_res)):
            pub_hex = res.get("public_key_hex")
            assert pub_hex and len(bytes.fromhex(pub_hex)) == 64, (
                f"{who} reported unexpected public key material: {pub_hex}{diag}"
            )
        enc_a, sign_a = bytes.fromhex(a_res["public_key_hex"])[:32], bytes.fromhex(a_res["public_key_hex"])[32:]
        assert _rns_identity_hash(enc_a, sign_a) == a_res.get("identity_hash"), (
            f"client identity hash inconsistent with its public key.{diag}"
        )

    # --- One concise verdict (always visible, even without -s) -----------
    provider_label = (
        "SoftHSM2 token-backed identity" if provider == "softhsm"
        else "plain RNS software identity"
    )
    verdict = [
        f"identity:  {provider_label}",
        f"link:      server B 127.0.0.1:{link_port} <-> client A, established + "
        f"client identified (signed over the link)",
        f"payload:   {len(PAYLOAD)} bytes sent and echoed back, bytes matched",
        f"app msg:   user A -> B, {len(APP_MESSAGE)} bytes E2E-encrypted; "
        f"B decrypted and read it",
        "isolation: decoy addressed to A was undecryptable by B (wrong key)",
        f"identity:  client {a_res.get('identity_hash')} == server-observed "
        f"{b_res.get('remote_identity_hash')}",
    ]
    if provider == "softhsm":
        verdict.append(
            "token:     identities made by reticulum_pkcs11_identity; keys are "
            "token-resident & non-extractable; B's decrypt ran on the token"
        )
    else:
        verdict.append(
            "identity:  plain RNS software identity (in-memory private key)"
        )
    _emit(
        "E2E PASS \u2014 two independent RNS instances talked over loopback TCP",
        verdict,
        cap=capsys,
    )

