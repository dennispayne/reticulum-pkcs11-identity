"""Voice-radio ecosystem peer process for the PKCS#11-backed identity e2e suite.

This module is **not** a test (the leading underscore keeps pytest from
collecting it). Like :mod:`tests.e2e._rns_peer`, it runs as a *separate*
process — Reticulum keeps ``Transport`` and destination tables in
process-global state, so two independent instances must be separate processes.

Framing — a voice-based handheld radio over Reticulum
-----------------------------------------------------
The project's end goal is a hand-held voice radio whose **user identities live
on a YubiKey**. The dominant real-world stack for that is `LXST
<https://github.com/markqvist/LXST>`_ (Lightweight Extensible Signal Transport
— Mark Qvist's Reticulum voice / two-way-radio framework) together with `LXMF
<https://github.com/markqvist/LXMF>`_ for store-and-forward messaging. Both are
built directly on ``RNS.Identity``/``RNS.Link``, so this package's transparent
PKCS#11 identity slots straight underneath them.

Audio hardware is irrelevant to what we must prove here. A radio "call" in LXST
is just an **RNS Link** to a callee's *call endpoint* destination, the caller is
authenticated by ``link.identify()`` (which **signs** with the identity key —
the YubiKey moment: cryptographic caller-ID), and voice is a stream of codec
frames carried as ``RNS.Packet``\\s over that link. We therefore reproduce the
LXST wire shape faithfully (the ``CallEndpoint`` destination aspects and the
``FIELD_SIGNALLING`` / ``FIELD_FRAMES`` umsgpack envelope from ``LXST/Call.py``
and ``LXST/Network.py``) while streaming *simulated* Codec2 frames whose exact
bytes we assert round-trip. Every scenario is chosen so that a specific
private-key operation is forced onto the token:

  ``presence_announce``   radio comes on-air, announces its callsign, and a peer
                          discovers it and sends an encrypted presence ping.
                          → announce **SIGN** + opportunistic **ECDH decrypt**.
  ``call_setup``          authenticated push-to-talk call setup: cryptographic
                          caller-ID, mutual challenge auth, tamper rejection.
                          → caller **SIGN** (identify) + callee **SIGN** (nonce).
  ``voice_stream``        live PTT audio: a stream of Codec2 frames over the
                          identity-authenticated call link, reassembled exactly.
                          → caller **SIGN** secures the live voice stream.
  ``voicemail_resource``  store-and-forward voice message delivered as an
                          ``RNS.Resource`` (bulk transfer) over the call link.
                          → caller **SIGN** secures the voicemail transfer.
  ``ptt_control``         talk-group control signalling (PTT key-up/down, join)
                          as structured ``RNS.Channel`` messages.
                          → caller **SIGN** (identify).
  ``call_proof``          confirmed delivery of call-control signalling via a
                          token-signed Reticulum delivery proof.
                          → callee **SIGN** (delivery proof).
  ``lxmf_message``        a real, signed LXMF message (text / voice-note
                          notification) between two radios.
                          → source **SIGN** (LXMF signs every message).

The peer always writes a JSON result to ``result_file`` so the parent can make
assertions even if the peer crashes or times out.

Usage::

    python _rns_ecosystem_peer.py <config.json>
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import traceback

import RNS
from RNS.vendor import umsgpack

# Reuse the proven identity/config builders from the flagship peer so both
# suites construct identities (software or PKCS#11 token-backed) identically.
from tests.e2e._rns_peer import _build_identity, _log, _write_config

# --------------------------------------------------------------------------
# LXST-faithful call vocabulary (mirrors LXST/Call.py + LXST/Network.py)
# --------------------------------------------------------------------------
FIELD_SIGNALLING = 0x00  # umsgpack key for in-band call signalling
FIELD_FRAMES = 0x01      # umsgpack key for codec frame payloads

# Call-control signalling opcodes (the in-band "ring/answer/hangup" of a call).
SIG_RINGING = 0x01
SIG_ANSWER = 0x02
SIG_BUSY = 0x03
SIG_HANGUP = 0x04

# Talk-group / PTT control opcodes carried over an RNS.Channel.
SIG_JOIN_TG = 0x10
SIG_PTT_DOWN = 0x11
SIG_PTT_UP = 0x12

# Stand-in codec id prepended to each frame, exactly as LXST prepends a
# ``codec_header_byte``. We do not run a real codec; the bytes are simulated
# Codec2 voice frames whose round-trip we assert.
CODEC2_3200 = 0x07


class SignalMessage(RNS.MessageBase):
    """Structured talk-group / PTT control message carried over an RNS.Channel.

    Mirrors how a real two-way-radio app multiplexes call-control alongside
    voice: an opcode (PTT down/up, talk-group join, hangup) plus a small label.
    Defined at module scope so both the caller and callee processes register the
    *same* ``MSGTYPE`` and can pack/unpack each other's messages.
    """

    MSGTYPE = 0xCA11  # < 0xf000 (the RNS system-reserved range)

    def __init__(self, opcode: int = 0, label: bytes = b""):
        self.opcode = int(opcode)
        self.label = label if isinstance(label, (bytes, bytearray)) else bytes(label)

    def pack(self) -> bytes:
        return bytes([self.opcode & 0xFF]) + bytes(self.label)

    def unpack(self, raw):
        raw = bytes(raw)
        self.opcode = raw[0] if raw else 0
        self.label = raw[1:]


# --------------------------------------------------------------------------
# Small shared helpers
# --------------------------------------------------------------------------
def _deadline(cfg: dict) -> float:
    return time.time() + cfg["timeout"]


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.time())


def _endpoint(identity, cfg):
    """Build the callee's inbound *call endpoint* SINGLE destination.

    Aspects mirror LXST's ``CallEndpoint`` (``APP_NAME, "call", "endpoint"``).
    """
    return RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        cfg["app_name"],
        *cfg["aspects"],
    )


def _out_dest(remote_identity, cfg):
    """Build the caller's outbound destination matching the callee endpoint."""
    return RNS.Destination(
        remote_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        cfg["app_name"],
        *cfg["aspects"],
    )


def _ready(cfg: dict, dest, result: dict, identity) -> None:
    """Publish the destination hash for the parent/peer and record provenance."""
    with open(cfg["ready_file"], "w") as fh:
        fh.write(dest.hash.hex())
    result["destination_hash"] = dest.hash.hex()
    result["identity_hash"] = identity.hash.hex()
    _log(f"endpoint ready: dest={dest.hash.hex()} id={identity.hash.hex()}")


def _announce_until(dest, done: threading.Event, deadline: float, app_data=None) -> None:
    """Announce the destination until the exchange completes or we time out."""
    while time.time() < deadline and not done.is_set():
        dest.announce(app_data=app_data)
        done.wait(timeout=3.0)


def _resolve(dest_hash: bytes, deadline: float):
    """Resolve a path to, and recall the identity of, a remote destination."""
    server_identity = None
    while time.time() < deadline:
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
        server_identity = RNS.Identity.recall(dest_hash)
        if server_identity is not None and RNS.Transport.has_path(dest_hash):
            return server_identity
        time.sleep(0.4)
    return server_identity


def _open_link_and_identify(out, identity, deadline: float):
    """Open an RNS link and identify over it (this *signs* with the key)."""
    established = threading.Event()

    def on_established(link):
        # The caller-ID moment: link.identify signs a proof with the identity
        # key. For the softhsm/YubiKey provider this runs on the token.
        link.identify(identity)
        established.set()

    link = RNS.Link(out, established_callback=on_established)
    established.wait(timeout=_remaining(deadline))
    return link, established.is_set()


def _request(link, path: str, data, deadline: float) -> dict:
    """Issue a link request and block for its response."""
    ev = threading.Event()
    box = {"resp": None, "failed": False}

    def on_response(receipt):
        box["resp"] = receipt.response
        ev.set()

    def on_failed(receipt):
        box["failed"] = True
        ev.set()

    link.request(
        path,
        data=data,
        response_callback=on_response,
        failed_callback=on_failed,
        timeout=max(1.0, min(20.0, _remaining(deadline))),
    )
    ev.wait(timeout=_remaining(deadline))
    return box


def _signal(link, opcode: int) -> None:
    """Send an in-band call-signalling packet (ring/answer/hangup)."""
    RNS.Packet(
        link,
        umsgpack.packb({FIELD_SIGNALLING: [opcode]}),
        create_receipt=False,
    ).send()


def _teardown(link) -> None:
    try:
        link.teardown()
    except Exception:  # pragma: no cover - defensive
        pass


# ==========================================================================
# Scenario 1 — presence_announce
# ==========================================================================
def srv_presence_announce(cfg, identity, result):
    """Radio comes on-air: announce callsign/status, accept an encrypted ping."""
    app_data = bytes.fromhex(cfg["app_data"])      # callsign + capabilities blob
    expected_ping = bytes.fromhex(cfg["payload"])  # opportunistic presence ping
    done = threading.Event()
    state = {"ping": None}

    dest = _endpoint(identity, cfg)
    # The callsign rides EVERY announce and path-response, so a peer that
    # resolves us via a path request still recovers it (set_default_app_data),
    # in addition to the per-announce copy below.
    dest.set_default_app_data(app_data)
    # Prove receipt of the (token-decrypted) ping back to the sender.
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)

    def on_packet(message, packet):
        # RNS has already decrypted this opportunistic packet for us using the
        # destination identity's X25519 key — token ECDH for the softhsm radio.
        state["ping"] = bytes(message) if message else None
        done.set()

    dest.set_packet_callback(on_packet)
    _ready(cfg, dest, result, identity)
    _announce_until(dest, done, _deadline(cfg), app_data=app_data)
    # Linger briefly so the delivery proof flushes to the sender.
    time.sleep(1.0)

    result["ping_recovered"] = state["ping"].hex() if state["ping"] else None
    result["ok"] = state["ping"] == expected_ping


def cli_presence_announce(cfg, identity, result):
    """Peer radio discovers the on-air radio and sends an encrypted ping."""
    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = _deadline(cfg)
    server_identity = _resolve(dest_hash, deadline)

    result["recalled_identity_hash"] = (
        server_identity.hash.hex() if server_identity else None
    )

    # The app_data (callsign) may land a beat after the identity; poll for it.
    app_data = None
    ad_deadline = min(deadline, time.time() + 15)
    while time.time() < ad_deadline:
        app_data = RNS.Identity.recall_app_data(dest_hash)
        if app_data:
            break
        time.sleep(0.3)
    result["recalled_app_data"] = app_data.hex() if app_data else None

    if server_identity is None:
        result["ok"] = False
        result["error"] = "could not recall on-air radio identity"
        return

    out = _out_dest(server_identity, cfg)
    ping = bytes.fromhex(cfg["payload"])
    proof = threading.Event()

    # Send the encrypted presence ping, retrying until the on-air radio proves
    # receipt (best-effort opportunistic packets, made reliable by retry).
    while time.time() < deadline and not proof.is_set():
        packet = RNS.Packet(out, ping)
        receipt = packet.send()
        if receipt:
            receipt.set_delivery_callback(lambda r: proof.set())
        proof.wait(timeout=2.0)

    result["sent_ping"] = ping.hex()
    result["ping_delivered"] = proof.is_set()
    result["ok"] = bool(
        server_identity is not None
        and app_data == bytes.fromhex(cfg["app_data"])
        and proof.is_set()
    )


# ==========================================================================
# Scenario 2 — call_setup (authenticated PTT call setup)
# ==========================================================================
def srv_call_setup(cfg, identity, result):
    """Callee radio: capture caller-ID and answer cryptographic challenges."""
    done = threading.Event()
    state = {"caller": None, "auth_served": 0}
    dest = _endpoint(identity, cfg)

    def gen_auth(path, data, request_id, link_id, remote_identity, requested_at):
        # The callee proves ITS identity by signing the caller's nonce. For the
        # softhsm/YubiKey radio this signature is produced on the token.
        state["auth_served"] += 1
        return identity.sign(bytes(data))

    def gen_whoami(path, data, request_id, link_id, remote_identity, requested_at):
        return remote_identity.hash if remote_identity else b""

    def gen_bye(path, data, request_id, link_id, remote_identity, requested_at):
        done.set()
        return b"bye"

    dest.register_request_handler(
        "/call/auth", response_generator=gen_auth, allow=RNS.Destination.ALLOW_ALL
    )
    dest.register_request_handler(
        "/call/whoami", response_generator=gen_whoami, allow=RNS.Destination.ALLOW_ALL
    )
    dest.register_request_handler(
        "/call/bye", response_generator=gen_bye, allow=RNS.Destination.ALLOW_ALL
    )

    def on_link(link):
        link.set_remote_identified_callback(
            lambda l, i: state.update(caller=i.hash.hex())
        )

    dest.set_link_established_callback(on_link)
    _ready(cfg, dest, result, identity)
    _announce_until(dest, done, _deadline(cfg))

    result["caller_identity_seen"] = state["caller"]
    result["auth_challenges_served"] = state["auth_served"]
    result["ok"] = state["caller"] is not None and state["auth_served"] >= 1


def cli_call_setup(cfg, identity, result):
    """Caller radio: place an authenticated call and verify the callee."""
    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = _deadline(cfg)
    server_identity = _resolve(dest_hash, deadline)
    if server_identity is None:
        result["ok"] = False
        result["error"] = "could not recall callee identity"
        return

    out = _out_dest(server_identity, cfg)
    link, established = _open_link_and_identify(out, identity, deadline)
    result["link_established"] = established
    if not established:
        result["ok"] = False
        result["error"] = "call link not established / identify failed"
        return

    # Challenge the callee: it must sign our random nonce with its key.
    nonce = os.urandom(32)
    auth = _request(link, "/call/auth", nonce, deadline)
    sig = bytes(auth["resp"]) if auth["resp"] is not None else None
    result["callee_sig_valid"] = bool(sig) and bool(server_identity.validate(sig, nonce))
    tampered = bytes([nonce[0] ^ 0xFF]) + nonce[1:]
    result["callee_sig_tamper_rejected"] = bool(sig) and not bool(
        server_identity.validate(sig, tampered)
    )

    # The callee must report OUR identity hash as the authenticated caller.
    who = _request(link, "/call/whoami", b"", deadline)
    who_resp = bytes(who["resp"]) if who["resp"] is not None else None
    result["whoami"] = who_resp.hex() if who_resp else None
    result["whoami_matches"] = who_resp == identity.hash

    _request(link, "/call/bye", b"", deadline)
    result["ok"] = bool(
        result["callee_sig_valid"]
        and result["callee_sig_tamper_rejected"]
        and result["whoami_matches"]
    )
    _teardown(link)


# ==========================================================================
# Scenario 3 — voice_stream (live Codec2 frames over the call link)
# ==========================================================================
def srv_voice_stream(cfg, identity, result):
    """Callee radio: receive a live voice frame stream and reassemble it."""
    n_frames = int(cfg["frame_count"])
    done = threading.Event()
    state = {"frames": [], "caller": None}
    dest = _endpoint(identity, cfg)

    def on_link(link):
        link.set_remote_identified_callback(
            lambda l, i: state.update(caller=i.hash.hex())
        )

        def on_packet(data, packet):
            try:
                unpacked = umsgpack.unpackb(data)
            except Exception:
                return
            if not isinstance(unpacked, dict):
                return
            if FIELD_FRAMES in unpacked:
                frame = bytes(unpacked[FIELD_FRAMES])  # codec_header + payload
                state["frames"].append(frame)
                if len(state["frames"]) >= n_frames:
                    done.set()
            elif FIELD_SIGNALLING in unpacked:
                signals = unpacked[FIELD_SIGNALLING]
                signals = signals if isinstance(signals, list) else [signals]
                if SIG_HANGUP in signals:
                    done.set()

        link.set_packet_callback(on_packet)
        link.set_link_closed_callback(lambda l: done.set())

    dest.set_link_established_callback(on_link)
    _ready(cfg, dest, result, identity)
    _announce_until(dest, done, _deadline(cfg))

    # Strip the one-byte codec header from each frame and concatenate.
    frames = state["frames"][:n_frames]
    voice = b"".join(f[1:] for f in frames)
    result["caller_identity_seen"] = state["caller"]
    result["frames_received"] = len(state["frames"])
    result["voice_sha256"] = hashlib.sha256(voice).hexdigest()
    result["ok"] = len(state["frames"]) >= n_frames and state["caller"] is not None


def cli_voice_stream(cfg, identity, result):
    """Caller radio: PTT — stream simulated Codec2 voice frames over the link."""
    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = _deadline(cfg)
    server_identity = _resolve(dest_hash, deadline)
    if server_identity is None:
        result["ok"] = False
        result["error"] = "could not recall callee identity"
        return

    out = _out_dest(server_identity, cfg)
    voice = bytes.fromhex(cfg["voice_hex"])
    frame_size = int(cfg["frame_size"])
    frames = [voice[i:i + frame_size] for i in range(0, len(voice), frame_size)]

    finished = threading.Event()

    def on_established(link):
        link.identify(identity)  # caller-ID: token SIGN

        def stream():
            # Settle so identify lands server-side, then ring and stream.
            time.sleep(0.2)
            _signal(link, SIG_RINGING)
            for fr in frames:
                framed = bytes([CODEC2_3200]) + fr
                RNS.Packet(
                    link,
                    umsgpack.packb({FIELD_FRAMES: framed}),
                    create_receipt=False,
                ).send()
                time.sleep(0.02)  # ~20 ms voice frame cadence
            time.sleep(0.3)       # let the last frames flush
            _signal(link, SIG_HANGUP)
            finished.set()

        threading.Thread(target=stream, daemon=True).start()

    link = RNS.Link(out, established_callback=on_established)
    finished.wait(timeout=_remaining(deadline))
    time.sleep(0.3)

    result["frames_sent"] = len(frames)
    result["voice_sha256"] = hashlib.sha256(voice).hexdigest()
    result["ok"] = finished.is_set()
    _teardown(link)


# ==========================================================================
# Scenario 4 — voicemail_resource (store-and-forward voice message)
# ==========================================================================
def srv_voicemail_resource(cfg, identity, result):
    """Callee radio: deliver a stored voice clip as an RNS.Resource."""
    clip = bytes.fromhex(cfg["clip_hex"])
    done = threading.Event()
    state = {"caller": None}
    dest = _endpoint(identity, cfg)

    def on_link(link):
        link.set_remote_identified_callback(
            lambda l, i: state.update(caller=i.hash.hex())
        )

        def on_packet(data, packet):
            if bytes(data) == b"VMAIL_GET":
                # Pass the clip as raw bytes: RNS.Resource treats any object
                # with .read() as a file and stats data.name, which BytesIO
                # lacks. Bytes take the single-segment in-memory path.
                RNS.Resource(clip, link, callback=lambda r: done.set())

        link.set_packet_callback(on_packet)
        link.set_link_closed_callback(lambda l: done.set())

    dest.set_link_established_callback(on_link)
    _ready(cfg, dest, result, identity)
    _announce_until(dest, done, _deadline(cfg))
    time.sleep(0.3)

    result["caller_identity_seen"] = state["caller"]
    result["clip_sha256"] = hashlib.sha256(clip).hexdigest()
    result["clip_size"] = len(clip)
    result["ok"] = state["caller"] is not None


def cli_voicemail_resource(cfg, identity, result):
    """Caller radio: retrieve a voicemail clip over the identified call link."""
    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = _deadline(cfg)
    server_identity = _resolve(dest_hash, deadline)
    if server_identity is None:
        result["ok"] = False
        result["error"] = "could not recall callee identity"
        return

    out = _out_dest(server_identity, cfg)
    got = {"data": None}
    concluded = threading.Event()

    def on_established(link):
        link.identify(identity)  # token SIGN secures the voicemail transfer
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)

        def on_concluded(resource):
            if resource.status == RNS.Resource.COMPLETE:
                got["data"] = resource.data.read()
            concluded.set()

        link.set_resource_concluded_callback(on_concluded)
        RNS.Packet(link, b"VMAIL_GET").send()

    link = RNS.Link(out, established_callback=on_established)
    concluded.wait(timeout=_remaining(deadline))

    data = got["data"]
    result["clip_sha256"] = hashlib.sha256(data).hexdigest() if data else None
    result["clip_size"] = len(data) if data else 0
    result["ok"] = bool(data)
    _teardown(link)


# ==========================================================================
# Scenario 5 — ptt_control (talk-group control over an RNS.Channel)
# ==========================================================================
def srv_ptt_control(cfg, identity, result):
    """Callee radio: receive talk-group/PTT control messages and acknowledge."""
    expected = int(cfg["control_count"])
    done = threading.Event()
    state = {"caller": None, "received": []}
    dest = _endpoint(identity, cfg)

    def on_link(link):
        link.set_remote_identified_callback(
            lambda l, i: state.update(caller=i.hash.hex())
        )
        channel = link.get_channel()
        channel.register_message_type(SignalMessage)

        def handler(message):
            if isinstance(message, SignalMessage):
                state["received"].append(message.opcode)
                ack = SignalMessage(opcode=message.opcode, label=b"ACK:" + message.label)
                link.get_channel().send(ack)
                if message.opcode == SIG_HANGUP:
                    done.set()
                return True
            return False

        channel.add_message_handler(handler)
        link.set_link_closed_callback(lambda l: done.set())

    dest.set_link_established_callback(on_link)
    _ready(cfg, dest, result, identity)
    _announce_until(dest, done, _deadline(cfg))

    result["caller_identity_seen"] = state["caller"]
    result["control_opcodes"] = state["received"]
    result["ok"] = state["caller"] is not None and len(state["received"]) >= expected


def cli_ptt_control(cfg, identity, result):
    """Caller radio: send a talk-group/PTT control sequence and collect acks."""
    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = _deadline(cfg)
    server_identity = _resolve(dest_hash, deadline)
    if server_identity is None:
        result["ok"] = False
        result["error"] = "could not recall callee identity"
        return

    out = _out_dest(server_identity, cfg)
    sequence = [
        (SIG_JOIN_TG, b"tg9"),
        (SIG_PTT_DOWN, b"mic"),
        (SIG_PTT_UP, b"mic"),
        (SIG_HANGUP, b"bye"),
    ]
    acks = {"opcodes": []}
    done = threading.Event()

    def on_established(link):
        link.identify(identity)  # token SIGN
        channel = link.get_channel()
        channel.register_message_type(SignalMessage)

        def on_msg(message):
            if isinstance(message, SignalMessage):
                acks["opcodes"].append(message.opcode)
                if message.opcode == SIG_HANGUP:
                    done.set()
                return True
            return False

        channel.add_message_handler(on_msg)

        def worker():
            for opcode, label in sequence:
                for _ in range(250):
                    if channel.is_ready_to_send():
                        break
                    time.sleep(0.02)
                channel.send(SignalMessage(opcode, label))
                time.sleep(0.05)

        threading.Thread(target=worker, daemon=True).start()

    link = RNS.Link(out, established_callback=on_established)
    done.wait(timeout=_remaining(deadline))
    time.sleep(0.2)

    result["acks"] = acks["opcodes"]
    result["control_sent"] = [op for op, _ in sequence]
    result["ok"] = len(acks["opcodes"]) >= len(sequence)
    _teardown(link)


# ==========================================================================
# Scenario 6 — call_proof (token-signed delivery proof of call control)
# ==========================================================================
def srv_call_proof(cfg, identity, result):
    """Callee radio: prove (sign) receipt of call-control signalling packets."""
    done = threading.Event()
    state = {"count": 0}
    dest = _endpoint(identity, cfg)
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)

    def on_packet(message, packet):
        state["count"] += 1
        # Linger briefly so the (token-signed) proof flushes, then finish.
        threading.Timer(2.0, done.set).start()

    dest.set_packet_callback(on_packet)
    _ready(cfg, dest, result, identity)
    _announce_until(dest, done, _deadline(cfg))

    result["control_packets_received"] = state["count"]
    result["ok"] = state["count"] >= 1


def cli_call_proof(cfg, identity, result):
    """Caller radio: send call-control signalling and await the signed proof."""
    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = _deadline(cfg)
    server_identity = _resolve(dest_hash, deadline)
    if server_identity is None:
        result["ok"] = False
        result["error"] = "could not recall callee identity"
        return

    out = _out_dest(server_identity, cfg)
    control = umsgpack.packb({FIELD_SIGNALLING: [SIG_HANGUP]})
    proof = threading.Event()

    while time.time() < deadline and not proof.is_set():
        packet = RNS.Packet(out, control)
        receipt = packet.send()
        if receipt:
            receipt.set_delivery_callback(lambda r: proof.set())
        proof.wait(timeout=2.0)

    result["proof_received"] = proof.is_set()
    result["ok"] = proof.is_set()


# ==========================================================================
# Scenario 7 — lxmf_message (real signed LXMF message between two radios)
# ==========================================================================
def _lxmf_router(cfg, identity, tag):
    import LXMF

    storage = os.path.join(cfg["configdir"], f"lxmf_{tag}")
    os.makedirs(storage, exist_ok=True)
    router = LXMF.LXMRouter(identity=identity, storagepath=storage)
    return router


def srv_lxmf_message(cfg, identity, result):
    """Recipient radio: receive and validate a signed LXMF message."""
    import LXMF  # noqa: F401  (presence required; guarded by parent skip)

    done = threading.Event()
    state = {"content": None, "source": None, "title": None, "validated": None}
    router = _lxmf_router(cfg, identity, "b")
    delivery_dest = router.register_delivery_identity(identity, display_name="Radio-B")

    def on_delivery(message):
        content = message.content
        state["content"] = bytes(content) if content is not None else None
        state["source"] = message.source_hash.hex() if message.source_hash else None
        title = message.title
        state["title"] = bytes(title) if title else b""
        state["validated"] = bool(getattr(message, "signature_validated", True))
        done.set()

    router.register_delivery_callback(on_delivery)

    with open(cfg["ready_file"], "w") as fh:
        fh.write(delivery_dest.hash.hex())
    result["destination_hash"] = delivery_dest.hash.hex()
    result["identity_hash"] = identity.hash.hex()

    deadline = _deadline(cfg)
    while time.time() < deadline and not done.is_set():
        router.announce(delivery_dest.hash)
        done.wait(timeout=3.0)

    result["lxmf_content"] = state["content"].hex() if state["content"] else None
    result["lxmf_source"] = state["source"]
    result["caller_identity_seen"] = state["source"]
    result["lxmf_signature_validated"] = state["validated"]
    result["ok"] = state["content"] is not None and state["source"] is not None


def cli_lxmf_message(cfg, identity, result):
    """Sender radio: send a signed LXMF message (text / voice-note) to a peer."""
    import LXMF

    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = _deadline(cfg)
    server_identity = _resolve(dest_hash, deadline)
    if server_identity is None:
        result["ok"] = False
        result["error"] = "could not recall recipient LXMF identity"
        return

    router = _lxmf_router(cfg, identity, "a")
    source_dest = router.register_delivery_identity(identity, display_name="Radio-A")

    # Announce our delivery identity FIRST, then let it propagate over the
    # (direct) link. Without our announce the recipient cannot recall our
    # public key, reports SOURCE_UNKNOWN, and signature_validated stays False.
    router.announce(source_dest.hash)
    prop_deadline = min(deadline, time.time() + 6)
    while time.time() < prop_deadline:
        time.sleep(0.5)

    dest_out = RNS.Destination(
        server_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery",
    )
    content = bytes.fromhex(cfg["payload"])
    lxm = LXMF.LXMessage(
        dest_out,
        source_dest,
        content,
        title="voice-note",
        desired_method=LXMF.LXMessage.DIRECT,
    )

    delivered = threading.Event()
    failed = threading.Event()
    lxm.register_delivery_callback(lambda m: delivered.set())
    lxm.register_failed_callback(lambda m: failed.set())

    router.handle_outbound(lxm)

    while time.time() < deadline and not delivered.is_set() and not failed.is_set():
        delivered.wait(timeout=1.0)

    result["lxmf_delivered"] = delivered.is_set()
    result["lxmf_failed"] = failed.is_set()
    result["lxmf_source_hash"] = source_dest.hash.hex()
    result["lxmf_content"] = content.hex()
    result["ok"] = delivered.is_set()


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------
SERVER_SCENARIOS = {
    "presence_announce": srv_presence_announce,
    "call_setup": srv_call_setup,
    "voice_stream": srv_voice_stream,
    "voicemail_resource": srv_voicemail_resource,
    "ptt_control": srv_ptt_control,
    "call_proof": srv_call_proof,
    "lxmf_message": srv_lxmf_message,
}

CLIENT_SCENARIOS = {
    "presence_announce": cli_presence_announce,
    "call_setup": cli_call_setup,
    "voice_stream": cli_voice_stream,
    "voicemail_resource": cli_voicemail_resource,
    "ptt_control": cli_ptt_control,
    "call_proof": cli_call_proof,
    "lxmf_message": cli_lxmf_message,
}


def main() -> int:
    cfg_path = sys.argv[1]
    with open(cfg_path) as fh:
        cfg = json.load(fh)

    result: dict = {"role": cfg["role"], "scenario": cfg["scenario"], "ok": False}
    backend = None
    try:
        _write_config(cfg)

        RNS.Reticulum(cfg["configdir"])
        identity, backend = _build_identity(cfg)

        # Provenance so the parent can verify the identity is genuinely what the
        # variant claims (token-backed for softhsm, not a silent software
        # fallback). Mirrors tests.e2e._rns_peer.main.
        result["identity_provider"] = cfg["identity"]["provider"]
        result["is_hardware"] = bool(getattr(identity, "_is_local_hardware", False))
        result["public_key_hex"] = identity.get_public_key().hex()
        result["identity_class"] = type(identity).__name__
        result["identity_module"] = type(identity).__module__
        result["has_in_memory_private_key"] = bool(
            getattr(identity, "prv_bytes", None)
            or getattr(identity, "sig_prv_bytes", None)
        )
        result["identity_hash"] = identity.hash.hex()

        scenario = cfg["scenario"]
        registry = SERVER_SCENARIOS if cfg["role"] == "server" else CLIENT_SCENARIOS
        handler = registry.get(scenario)
        if handler is None:
            raise ValueError(f"unknown scenario {scenario!r} for role {cfg['role']!r}")
        handler(cfg, identity, result)
    except Exception as exc:
        result["ok"] = False
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["traceback"] = traceback.format_exc()
        _log(result["traceback"])
    finally:
        if backend is not None:
            try:
                backend.close()
            except Exception:  # pragma: no cover - defensive
                pass
        with open(cfg["result_file"], "w") as fh:
            json.dump(result, fh)
        _log(f"result: {result}")

    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
