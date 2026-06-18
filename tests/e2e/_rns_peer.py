"""Standalone Reticulum peer process for two-instance end-to-end tests.

This module is **not** a test (the leading underscore keeps pytest from
collecting it). It is launched as a separate Python process by
``test_two_instance_e2e.py`` because Reticulum keeps its ``Transport`` and
destination tables in process-global state, so two independent instances
cannot coexist in one interpreter — they must be separate processes.

Each peer:

  * writes its own isolated Reticulum config (``share_instance = No``, a single
    loopback ``TCP*Interface``, unique control ports) so it never touches any
    Reticulum instance already running on the machine;
  * builds an identity that is either a plain software ``RNS.Identity`` or a
    PKCS#11 token-backed identity (via :func:`make_lxmf_identity_class`);
  * plays one of two roles connected over kernel loopback TCP:

      ``server`` — announces a destination, accepts an inbound ``RNS.Link``,
                   echoes the first data packet, and records the hash of the
                   identity the client proves over the link;
      ``client`` — finds a path to the server, opens a link, ``identify()``s
                   itself (this is the operation that *signs* with the
                   identity key — token-routed for the softhsm provider), sends
                   a payload, and waits for the echo.

The peer always writes a JSON result object to ``result_file`` so the parent
test can make assertions even if the peer crashes or times out.

Usage::

    python _rns_peer.py <config.json>
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import traceback


def _log(msg: str) -> None:
    """Diagnostic logging to stderr (stdout is reserved for clean signalling)."""
    print(f"[peer:{os.getpid()}] {msg}", file=sys.stderr, flush=True)


# One-byte tags prefixed to each application packet sent over the link.
MSG_ECHO = b"\x01"   # link-level echo request; the payload is echoed verbatim
MSG_APP = b"\x02"    # ciphertext encrypted to the SERVER's identity (real msg)
MSG_DECOY = b"\x03"  # ciphertext encrypted to the CLIENT's own identity (decoy)


def _write_config(cfg: dict) -> None:
    """Write an isolated Reticulum config file into the peer's configdir."""
    configdir = cfg["configdir"]
    os.makedirs(configdir, exist_ok=True)
    iface = cfg["interface"]

    lines = [
        "[reticulum]",
        "  enable_transport = No",
        "  share_instance = No",
        f"  shared_instance_port = {cfg['shared_instance_port']}",
        f"  instance_control_port = {cfg['instance_control_port']}",
        "  panel_enabled = No",
        "",
        "[logging]",
        f"  loglevel = {cfg.get('loglevel', 3)}",
        "",
        "[interfaces]",
        "",
        "  [[e2e-loopback]]",
        f"    type = {iface['type']}",
        "    interface_enabled = true",
    ]
    if iface["type"] == "TCPServerInterface":
        lines += [
            f"    listen_ip = {iface['listen_ip']}",
            f"    listen_port = {iface['listen_port']}",
        ]
    else:  # TCPClientInterface
        lines += [
            f"    target_host = {iface['target_host']}",
            f"    target_port = {iface['target_port']}",
        ]
    lines.append("")

    with open(os.path.join(configdir, "config"), "w") as fh:
        fh.write("\n".join(lines))


def _build_identity(cfg: dict):
    """Create the peer's RNS identity from the configured provider."""
    import RNS

    idcfg = cfg["identity"]
    provider = idcfg["provider"]

    if provider == "software":
        return RNS.Identity(create_keys=True), None

    if provider == "softhsm":
        # Token-backed identity: signing and ECDH decryption happen on the
        # PKCS#11 token via the package's explicit factory.
        if idcfg.get("dll_dir"):
            add_dll_directory = getattr(os, "add_dll_directory", None)
            if add_dll_directory and os.path.isdir(idcfg["dll_dir"]):
                add_dll_directory(idcfg["dll_dir"])
        if idcfg.get("softhsm2_conf"):
            os.environ["SOFTHSM2_CONF"] = idcfg["softhsm2_conf"]

        from reticulum_pkcs11_identity.backend import PKCS11Backend
        from reticulum_pkcs11_identity.identity import make_lxmf_identity_class

        backend = PKCS11Backend(
            module_path=idcfg["module"],
            token_label=idcfg["token_label"],
        )
        backend.open_session(pin=idcfg["pin"])
        identity_cls = make_lxmf_identity_class(
            backend=backend,
            sign_key_label=idcfg["sign_label"],
            enc_key_label=idcfg["enc_label"],
        )
        return identity_cls(create_keys=True), backend

    raise ValueError(f"unknown identity provider: {provider!r}")


def _run_server(cfg: dict, identity, result: dict) -> None:
    import RNS

    app_name = cfg["app_name"]
    aspects = cfg["aspects"]
    expected = bytes.fromhex(cfg["payload"])
    deadline = time.time() + cfg["timeout"]

    state = {
        "remote_identity_hash": None,
        "received": None,
        "echoed": False,
        "app_plaintext": None,    # decrypted app-layer message addressed to us
        "app_seen": False,
        "decoy_recovered": None,  # plaintext IF we wrongly decrypt the decoy
        "decoy_seen": False,
    }
    done = threading.Event()

    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        app_name,
        *aspects,
    )
    destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

    def _maybe_done():
        if (state["remote_identity_hash"] is not None
                and state["received"] is not None
                and state["app_seen"]
                and state["decoy_seen"]):
            done.set()

    def on_packet(message, packet):
        if not message:
            return
        tag, body = message[:1], message[1:]
        if tag == MSG_ECHO:
            _log(f"server received echo request ({len(body)} bytes)")
            state["received"] = body
            try:
                RNS.Packet(packet.link, body).send()  # echo the payload back
                state["echoed"] = True
            except Exception as exc:  # pragma: no cover - defensive
                _log(f"server echo failed: {exc}")
        elif tag == MSG_APP:
            # An application-layer message encrypted to OUR identity's public
            # key. For the softhsm provider the X25519 ECDH required to decrypt
            # it runs inside the PKCS#11 token (the identity holds no private
            # key in memory), so a successful decrypt proves the token key
            # secured this user traffic.
            state["app_plaintext"] = identity.decrypt(body)
            state["app_seen"] = True
            _log(f"server decrypted app message -> {state['app_plaintext']!r}")
        elif tag == MSG_DECOY:
            # A message encrypted to a DIFFERENT identity (the client's own).
            # We must NOT be able to recover it; decrypt() returns None.
            state["decoy_recovered"] = identity.decrypt(body)
            state["decoy_seen"] = True
            _log(f"server decoy decrypt -> {state['decoy_recovered']!r}")
        else:  # pragma: no cover - defensive
            _log(f"server: ignoring unknown message tag {tag!r}")
        _maybe_done()

    def on_remote_identified(link, remote_identity):
        state["remote_identity_hash"] = remote_identity.hash.hex()
        _log(f"server: remote identified as {state['remote_identity_hash']}")
        _maybe_done()

    def on_link(link):
        _log("server: inbound link established")
        link.set_packet_callback(on_packet)
        link.set_remote_identified_callback(on_remote_identified)

    destination.set_link_established_callback(on_link)

    # Publish the destination hash for the parent/client, then announce until
    # the exchange completes or we time out.
    with open(cfg["ready_file"], "w") as fh:
        fh.write(destination.hash.hex())
    result["destination_hash"] = destination.hash.hex()
    result["identity_hash"] = identity.hash.hex()
    _log(f"server ready: dest={destination.hash.hex()} id={identity.hash.hex()}")

    while time.time() < deadline and not done.is_set():
        destination.announce()
        done.wait(timeout=3.0)

    result["ok"] = bool(
        state["received"] == expected and state["remote_identity_hash"]
    )
    result["received_payload"] = (
        state["received"].hex() if state["received"] else None
    )
    result["remote_identity_hash"] = state["remote_identity_hash"]
    result["echoed"] = state["echoed"]
    # Application-layer messaging outcomes (proof of real user-app traffic):
    result["app_message_decrypted"] = (
        state["app_plaintext"].hex() if state["app_plaintext"] else None
    )
    result["decoy_recovered"] = (
        state["decoy_recovered"].hex() if state["decoy_recovered"] else None
    )
    result["decoy_decryptable"] = state["decoy_recovered"] is not None


def _run_client(cfg: dict, identity, result: dict) -> None:
    import RNS

    app_name = cfg["app_name"]
    aspects = cfg["aspects"]
    payload = bytes.fromhex(cfg["payload"])
    dest_hash = bytes.fromhex(cfg["peer_dest_hash"])
    deadline = time.time() + cfg["timeout"]

    result["identity_hash"] = identity.hash.hex()

    # 1. Resolve a path to the server's destination.
    server_identity = None
    while time.time() < deadline:
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
        server_identity = RNS.Identity.recall(dest_hash)
        if server_identity is not None and RNS.Transport.has_path(dest_hash):
            break
        time.sleep(0.5)

    if server_identity is None or not RNS.Transport.has_path(dest_hash):
        result["ok"] = False
        result["error"] = "no path/identity to server before timeout"
        return
    _log("client: path + server identity resolved")

    destination = RNS.Destination(
        server_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        app_name,
        *aspects,
    )

    app_message = bytes.fromhex(cfg["app_message"])
    decoy_message = bytes.fromhex(cfg["decoy_message"])

    echo = {"data": None}
    link_state = {"active": False}
    echo_event = threading.Event()

    def on_link_established(link):
        _log("client: link established; identifying")
        link_state["active"] = True
        link.identify(identity)  # signs a proof with our (token-backed) key

        def on_echo(message, packet):
            echo["data"] = message
            echo_event.set()

        link.set_packet_callback(on_echo)

        # Real application-layer traffic, end-to-end encrypted with RNS
        # identity public-key encryption (a layer ABOVE the link's own
        # transport encryption):
        #   * a genuine message addressed to the SERVER's identity, which the
        #     server must be able to decrypt and read;
        #   * a decoy addressed to OUR OWN identity, which the server must NOT
        #     be able to decrypt (it is not the intended recipient).
        RNS.Packet(link, MSG_APP + server_identity.encrypt(app_message)).send()
        RNS.Packet(link, MSG_DECOY + identity.encrypt(decoy_message)).send()
        # Echo request is sent LAST; its round-trip confirms the two messages
        # above were delivered (link packets keep send order over loopback).
        RNS.Packet(link, MSG_ECHO + payload).send()

    link = RNS.Link(destination, established_callback=on_link_established)

    # 2. Wait for link + echo.
    while time.time() < deadline and not echo_event.is_set():
        echo_event.wait(timeout=1.0)

    result["link_established"] = link_state["active"]
    result["echo_received"] = echo_event.is_set()
    result["echo_matches"] = echo["data"] == payload
    result["app_message_sent"] = app_message.hex()
    result["ok"] = bool(link_state["active"] and echo["data"] == payload)
    try:
        link.teardown()
    except Exception:  # pragma: no cover - defensive
        pass


def main() -> int:
    cfg_path = sys.argv[1]
    with open(cfg_path) as fh:
        cfg = json.load(fh)

    result: dict = {"role": cfg["role"], "ok": False}
    backend = None
    reticulum = None
    try:
        _write_config(cfg)
        import RNS

        reticulum = RNS.Reticulum(cfg["configdir"])
        identity, backend = _build_identity(cfg)

        # Record provenance so the parent can verify the identity is genuinely
        # what the variant claims (e.g. token-backed for softhsm, not a silent
        # software fallback). These are assurances, not behaviour.
        result["identity_provider"] = cfg["identity"]["provider"]
        result["is_hardware"] = bool(getattr(identity, "_is_local_hardware", False))
        result["public_key_hex"] = identity.get_public_key().hex()
        # Provenance: prove WHICH code produced this identity object, and that
        # it holds no private key in memory. A software/filesystem identity is
        # a stock ``RNS.Identity`` carrying prv_bytes/sig_prv_bytes; a token
        # identity is our package's class and exposes no private key material.
        result["identity_class"] = type(identity).__name__
        result["identity_module"] = type(identity).__module__
        result["has_in_memory_private_key"] = bool(
            getattr(identity, "prv_bytes", None)
            or getattr(identity, "sig_prv_bytes", None)
        )

        if cfg["role"] == "server":
            _run_server(cfg, identity, result)
        else:
            _run_client(cfg, identity, result)
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
