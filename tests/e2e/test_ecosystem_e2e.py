"""Voice-radio ecosystem end-to-end tests for the PKCS#11-backed identity.

These build on the flagship two-instance harness (see
``tests/e2e/test_two_instance_e2e.py``) but exercise the breadth of real
Reticulum-ecosystem usage a **voice handheld radio whose user identities live
on a YubiKey** depends on. The per-peer logic lives in
``tests/e2e/_rns_ecosystem_peer.py``; this module is the orchestrator.

Each scenario maps a concrete radio behaviour to a private-key operation that is
forced onto the token (SoftHSM2 here, a YubiKey in the field):

  presence_announce   on-air announce + encrypted presence ping
                      → announce SIGN + opportunistic ECDH decrypt
  call_setup          authenticated PTT call setup (crypto caller-ID, mutual
                      challenge auth, tamper rejection)
                      → caller SIGN (identify) + callee SIGN (nonce)
  voice_stream        live Codec2 voice frames over the call link
                      → caller SIGN secures the live stream
  voicemail_resource  store-and-forward voice clip as an RNS.Resource
                      → caller SIGN secures the bulk transfer
  ptt_control         talk-group / PTT control over an RNS.Channel
                      → caller SIGN (identify)
  call_proof          token-signed delivery proof of call-control signalling
                      → callee SIGN (delivery proof)
  lxmf_message        a real, signed LXMF message (voice-note notification)
                      → source SIGN (LXMF signs every message)

Both identity providers are parametrized, exactly as the flagship: ``software``
(plain ``RNS.Identity``, always runs) and ``softhsm`` (two token-backed
identities on one SoftHSM2 token; skipped unless an EdDSA-capable SoftHSM2 is
installed). For ``softhsm`` every scenario additionally asserts the identity was
produced by this package, holds no in-memory private key, and matches the hash
derived from the keys read off the token — so a green result cannot be a silent
software fallback.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

import pytest

from tests.e2e.test_two_instance_e2e import (
    HAS_RNS,
    JOIN_TIMEOUT,
    LOGLEVEL,
    PEER_TIMEOUT,
    READY_TIMEOUT,
    _drain,
    _emit,
    _free_port,
    _indent,
    _provision_softhsm_two_identities,
)

ECO_PEER = os.path.join(os.path.dirname(__file__), "_rns_ecosystem_peer.py")

# A radio "call endpoint" — mirrors LXST's CallEndpoint destination aspects.
CALL_APP = "lxst"
CALL_ASPECTS = ["call", "endpoint"]

# Talk-group / PTT control opcodes (mirror tests.e2e._rns_ecosystem_peer; kept
# as local constants so the parent never imports the peer's RNS.MessageBase).
SIG_HANGUP = 0x04
SIG_JOIN_TG = 0x10
SIG_PTT_DOWN = 0x11
SIG_PTT_UP = 0x12
PTT_SEQUENCE = [SIG_JOIN_TG, SIG_PTT_DOWN, SIG_PTT_UP, SIG_HANGUP]


# --------------------------------------------------------------------------
# Process spawn (points at the ecosystem peer; drains via the flagship helper)
# --------------------------------------------------------------------------
def _spawn(config: dict, tmp_path, tag: str) -> subprocess.Popen:
    cfg_path = tmp_path / f"{tag}_config.json"
    cfg_path.write_text(json.dumps(config))
    child_env = dict(os.environ)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    child_env["PYTHONPATH"] = repo_root + os.pathsep + child_env.get("PYTHONPATH", "")
    if config["identity"].get("softhsm2_conf"):
        child_env["SOFTHSM2_CONF"] = config["identity"]["softhsm2_conf"]
    out_fh = open(tmp_path / f"{tag}_stdout.log", "w")
    err_fh = open(tmp_path / f"{tag}_stderr.log", "w")
    proc = subprocess.Popen(
        [sys.executable, ECO_PEER, str(cfg_path)],
        stdout=out_fh,
        stderr=err_fh,
        env=child_env,
        text=True,
    )
    proc._e2e_capture = (
        out_fh,
        err_fh,
        tmp_path / f"{tag}_stdout.log",
        tmp_path / f"{tag}_stderr.log",
    )
    return proc


# --------------------------------------------------------------------------
# Per-scenario config builders → (extra_cfg, expected)
# --------------------------------------------------------------------------
def _build_presence_announce():
    callsign = b"CALLSIGN=KZ7RAD;STATUS=on-air;GRID=CN85;CAP=voice,codec2"
    ping = b"presence-ping: KD9XYZ requesting net roll-call on TG9"
    return ({"app_data": callsign.hex(), "payload": ping.hex()},
            {"callsign": callsign, "ping": ping})


def _build_call_setup():
    return ({}, {})


def _build_voice_stream():
    # Simulated Codec2 3200 bps voice: 8-byte frames every 20 ms. 40 frames is
    # ~0.8 s of "speech"; the exact bytes must reassemble on the far radio.
    voice = os.urandom(320)
    return ({"voice_hex": voice.hex(), "frame_size": 8, "frame_count": len(voice) // 8},
            {"voice": voice})


def _build_voicemail_resource():
    # ~16 KB voice clip → a multi-part RNS.Resource transfer.
    clip = os.urandom(16384)
    return ({"clip_hex": clip.hex()}, {"clip": clip})


def _build_ptt_control():
    return ({"control_count": len(PTT_SEQUENCE)}, {})


def _build_call_proof():
    return ({}, {})


def _build_lxmf_message():
    content = b"voice-note ready (3s): tap to listen  [KD9XYZ -> KZ7RAD]"
    return ({"payload": content.hex()}, {"content": content})


SCENARIO_BUILDERS = {
    "presence_announce": _build_presence_announce,
    "call_setup": _build_call_setup,
    "voice_stream": _build_voice_stream,
    "voicemail_resource": _build_voicemail_resource,
    "ptt_control": _build_ptt_control,
    "call_proof": _build_call_proof,
    "lxmf_message": _build_lxmf_message,
}


# --------------------------------------------------------------------------
# Per-scenario behaviour assertions
# --------------------------------------------------------------------------
def _assert_presence_announce(a, b, provider, exp, diag):
    assert a.get("recalled_identity_hash") == b.get("identity_hash"), (
        f"peer recalled the wrong on-air identity{diag}"
    )
    assert a.get("recalled_app_data") == exp["callsign"].hex(), (
        f"callsign/app-data not recovered from the announce{diag}"
    )
    # The on-air radio decrypted the opportunistic presence ping — for softhsm
    # this X25519 ECDH ran on the token.
    assert b.get("ping_recovered") == exp["ping"].hex(), (
        f"on-air radio failed to decrypt the presence ping{diag}"
    )
    assert a.get("ping_delivered") is True, f"presence ping not proven delivered{diag}"


def _assert_call_setup(a, b, provider, exp, diag):
    assert a.get("link_established") is True, f"call link not established{diag}"
    # Callee proved its identity by signing our nonce (token SIGN for softhsm).
    assert a.get("callee_sig_valid") is True, f"callee challenge signature invalid{diag}"
    assert a.get("callee_sig_tamper_rejected") is True, (
        f"tampered challenge was NOT rejected{diag}"
    )
    # Cryptographic caller-ID: the callee bound our token identity to the call.
    assert a.get("whoami_matches") is True, f"caller-ID not bound to our identity{diag}"
    assert a.get("whoami") == a.get("identity_hash"), f"caller-ID hash mismatch{diag}"
    assert b.get("caller_identity_seen") == a.get("identity_hash"), (
        f"callee saw the wrong caller identity{diag}"
    )
    assert b.get("auth_challenges_served", 0) >= 1, f"callee served no challenge{diag}"


def _assert_voice_stream(a, b, provider, exp, diag):
    expected_sha = hashlib.sha256(exp["voice"]).hexdigest()
    assert a.get("voice_sha256") == expected_sha, f"sender voice digest wrong{diag}"
    assert b.get("voice_sha256") == expected_sha, (
        f"voice stream did not reassemble byte-exact on the far radio{diag}"
    )
    assert b.get("frames_received") == a.get("frames_sent"), (
        f"frame count mismatch: sent={a.get('frames_sent')} "
        f"recv={b.get('frames_received')}{diag}"
    )
    assert b.get("caller_identity_seen") == a.get("identity_hash"), (
        f"voice stream not bound to the authenticated caller{diag}"
    )


def _assert_voicemail_resource(a, b, provider, exp, diag):
    expected_sha = hashlib.sha256(exp["clip"]).hexdigest()
    assert a.get("clip_sha256") == expected_sha, (
        f"voicemail clip did not transfer byte-exact{diag}"
    )
    assert b.get("clip_sha256") == expected_sha, f"server clip digest wrong{diag}"
    assert a.get("clip_size") == len(exp["clip"]), f"voicemail clip size wrong{diag}"
    assert b.get("caller_identity_seen") == a.get("identity_hash"), (
        f"voicemail transfer not bound to the authenticated caller{diag}"
    )


def _assert_ptt_control(a, b, provider, exp, diag):
    assert b.get("control_opcodes") == PTT_SEQUENCE, (
        f"callee did not receive the PTT control sequence in order: "
        f"{b.get('control_opcodes')}{diag}"
    )
    assert a.get("acks") == PTT_SEQUENCE, (
        f"caller did not receive an ack per control message: {a.get('acks')}{diag}"
    )
    assert b.get("caller_identity_seen") == a.get("identity_hash"), (
        f"control channel not bound to the authenticated caller{diag}"
    )


def _assert_call_proof(a, b, provider, exp, diag):
    # The caller received a delivery proof the callee SIGNED (token SIGN).
    assert a.get("proof_received") is True, (
        f"no token-signed delivery proof for the call-control packet{diag}"
    )
    assert b.get("control_packets_received", 0) >= 1, (
        f"callee received no call-control packet{diag}"
    )


def _assert_lxmf_message(a, b, provider, exp, diag):
    assert a.get("lxmf_delivered") is True, f"LXMF message not delivered{diag}"
    assert a.get("lxmf_failed") is not True, f"LXMF message reported failure{diag}"
    assert b.get("lxmf_content") == exp["content"].hex(), (
        f"LXMF message body not delivered intact{diag}"
    )
    # The recipient recovered the sender's LXMF source (a delivery destination
    # derived from the sender's identity) and validated the signature — which
    # only the sender's (token-held) private key could have produced.
    assert b.get("lxmf_source") == a.get("lxmf_source_hash"), (
        f"LXMF message source identity mismatch{diag}"
    )
    assert b.get("lxmf_signature_validated") is True, (
        f"LXMF message signature did not validate{diag}"
    )


SCENARIO_ASSERTERS = {
    "presence_announce": _assert_presence_announce,
    "call_setup": _assert_call_setup,
    "voice_stream": _assert_voice_stream,
    "voicemail_resource": _assert_voicemail_resource,
    "ptt_control": _assert_ptt_control,
    "call_proof": _assert_call_proof,
    "lxmf_message": _assert_lxmf_message,
}


# --------------------------------------------------------------------------
# Concise human-readable verdicts (always shown, like the flagship)
# --------------------------------------------------------------------------
def _verdict(scenario, a, b, provider, exp):
    token_line = (
        "token:     identities by reticulum_pkcs11_identity; keys token-resident "
        "& non-extractable; private-key op ran on the token"
        if provider == "softhsm"
        else "identity:  plain RNS software identity (in-memory private key)"
    )
    if scenario == "presence_announce":
        headline = [
            f"on-air:    radio announced callsign ({len(exp['callsign'])}B app-data); "
            "peer recalled it",
            "ping:      peer's encrypted presence ping decrypted by the on-air "
            "radio (ECDH)",
        ]
    elif scenario == "call_setup":
        headline = [
            "call:      authenticated PTT call set up over an RNS link",
            f"caller-ID: callee bound caller {a.get('identity_hash')}",
            "auth:      callee signed the caller's nonce; tampered nonce rejected",
        ]
    elif scenario == "voice_stream":
        headline = [
            f"voice:     {a.get('frames_sent')} Codec2 frames streamed over the "
            "call link",
            "integrity: far radio reassembled the stream byte-exact (sha256)",
            f"caller-ID: stream bound to caller {a.get('identity_hash')}",
        ]
    elif scenario == "voicemail_resource":
        headline = [
            f"voicemail: {a.get('clip_size')}-byte voice clip pulled as an "
            "RNS.Resource",
            "integrity: clip transferred byte-exact (sha256)",
        ]
    elif scenario == "ptt_control":
        headline = [
            f"talkgroup: PTT control sequence {PTT_SEQUENCE} delivered over an "
            "RNS.Channel",
            "ack:       caller received an ack for every control message",
        ]
    elif scenario == "call_proof":
        headline = [
            "delivery:  call-control packet confirmed by a token-signed proof",
        ]
    elif scenario == "lxmf_message":
        headline = [
            f"message:   signed LXMF voice-note delivered "
            f"({len(exp['content'])}B body)",
            f"signed-by: recipient validated sig from {b.get('lxmf_source')}",
        ]
    else:
        headline = []
    return [f"scenario:  {scenario}"] + headline + [token_line]


# --------------------------------------------------------------------------
# Shared provenance / believability assertions
# --------------------------------------------------------------------------
def _assert_provenance(provider, a, b, tok, diag):
    if provider == "softhsm":
        for who, res in (("client", a), ("server", b)):
            assert res.get("is_hardware") is True, (
                f"{who} claims softhsm but identity is not token-backed: {res}{diag}"
            )
            assert (res.get("identity_module") or "").startswith(
                "reticulum_pkcs11_identity"
            ), (
                f"{who} identity not produced by this package "
                f"(module={res.get('identity_module')}){diag}"
            )
            assert res.get("has_in_memory_private_key") is False, (
                f"{who} identity holds a private key in memory — not a token one{diag}"
            )
            assert res.get("identity_provider") == "softhsm", (
                f"{who} provider mismatch{diag}"
            )
        assert a.get("identity_hash") == tok["expected_hashes"]["nodeA"], (
            f"client identity != token-derived nodeA{diag}"
        )
        assert b.get("identity_hash") == tok["expected_hashes"]["nodeB"], (
            f"server identity != token-derived nodeB{diag}"
        )
    else:
        for who, res in (("client", a), ("server", b)):
            assert res.get("has_in_memory_private_key") is True, (
                f"{who} software identity unexpectedly has no in-memory key{diag}"
            )
    assert a.get("identity_hash") != b.get("identity_hash"), (
        f"both radios reported the same identity hash{diag}"
    )


# --------------------------------------------------------------------------
# The parametrized test
# --------------------------------------------------------------------------
@pytest.mark.skipif(not HAS_RNS, reason="RNS not installed")
@pytest.mark.integration
@pytest.mark.parametrize(
    "provider",
    ["software", "softhsm"],
    ids=["software", "SoftHSM2-token"],
)
@pytest.mark.parametrize("scenario", list(SCENARIO_BUILDERS), ids=list(SCENARIO_BUILDERS))
def test_voice_radio_ecosystem_e2e(scenario, provider, tmp_path, capsys):
    """Drive one voice-radio ecosystem scenario between two independent local
    Reticulum instances over loopback TCP, on either a software or a
    SoftHSM2-token-backed identity."""
    if scenario == "lxmf_message":
        pytest.importorskip("LXMF", reason="LXMF not installed")

    if provider == "software":
        id_a = {"provider": "software"}
        id_b = {"provider": "software"}
        tok = None
    else:
        tok = _provision_softhsm_two_identities(tmp_path)
        id_a = {**tok, "sign_label": "nodeA-sign", "enc_label": "nodeA-enc"}
        id_b = {**tok, "sign_label": "nodeB-sign", "enc_label": "nodeB-enc"}

    extra, expected = SCENARIO_BUILDERS[scenario]()

    link_port = _free_port()
    ready_file = tmp_path / "ready.txt"
    a_result_file = tmp_path / "a_result.json"
    b_result_file = tmp_path / "b_result.json"

    def _cfg(role, identity, result_file):
        cfg = {
            "role": role,
            "scenario": scenario,
            "configdir": str(tmp_path / f"{role}_config"),
            "shared_instance_port": _free_port(),
            "instance_control_port": _free_port(),
            "loglevel": LOGLEVEL,
            "identity": identity,
            "app_name": CALL_APP,
            "aspects": CALL_ASPECTS,
            "ready_file": str(ready_file),
            "result_file": result_file,
            "timeout": PEER_TIMEOUT,
        }
        cfg.update(extra)
        return cfg

    # --- callee radio (server) ----------------------------------------
    server_cfg = _cfg("server", id_b, str(b_result_file))
    server_cfg["interface"] = {
        "type": "TCPServerInterface",
        "listen_ip": "127.0.0.1",
        "listen_port": link_port,
    }
    server = _spawn(server_cfg, tmp_path, "B")

    dest_hash = None
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        if ready_file.exists() and ready_file.read_text().strip():
            dest_hash = ready_file.read_text().strip()
            break
        if server.poll() is not None:
            break
        time.sleep(0.2)

    if dest_hash is None:
        code, out, err = _drain(server, timeout=5)
        _emit(
            f"VOICE-RADIO E2E FAILED — callee never ready ({scenario}/{provider})",
            [f"callee exit: {code}", "STDOUT:", _indent(out), "STDERR:", _indent(err)],
            cap=capsys,
        )
        pytest.fail(f"callee never became ready (exit={code}).\n{out}\n{err}")

    # --- caller radio (client) ----------------------------------------
    client_cfg = _cfg("client", id_a, str(a_result_file))
    client_cfg["interface"] = {
        "type": "TCPClientInterface",
        "target_host": "127.0.0.1",
        "target_port": link_port,
    }
    client_cfg["peer_dest_hash"] = dest_hash
    client = _spawn(client_cfg, tmp_path, "A")

    a_code, a_out, a_err = _drain(client, timeout=JOIN_TIMEOUT)
    b_code, b_out, b_err = _drain(server, timeout=JOIN_TIMEOUT)

    diag = (
        f"\n--- callee exit={b_code} ---\nSTDOUT:\n{b_out}\nSTDERR:\n{b_err}"
        f"\n--- caller exit={a_code} ---\nSTDOUT:\n{a_out}\nSTDERR:\n{a_err}"
    )

    a_res = json.loads(a_result_file.read_text()) if a_result_file.exists() else {}
    b_res = json.loads(b_result_file.read_text()) if b_result_file.exists() else {}

    assert a_result_file.exists(), f"caller wrote no result.{diag}"
    assert b_result_file.exists(), f"callee wrote no result.{diag}"
    assert b_res.get("ok"), f"callee scenario {scenario!r} failed: {b_res}{diag}"
    assert a_res.get("ok"), f"caller scenario {scenario!r} failed: {a_res}{diag}"

    _assert_provenance(provider, a_res, b_res, tok, diag)
    SCENARIO_ASSERTERS[scenario](a_res, b_res, provider, expected, diag)

    _emit(
        f"VOICE-RADIO E2E PASS — {scenario} ({provider})",
        _verdict(scenario, a_res, b_res, provider, expected),
        cap=capsys,
    )
