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

    state = {"remote_identity_hash": None, "received": None, "echoed": False}
    done = threading.Event()

    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        app_name,
        *aspects,
    )
    destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

    def on_packet(message, packet):
        _log(f"server received {len(message)} bytes over link")
        state["received"] = message
        try:
            RNS.Packet(packet.link, message).send()  # echo back
            state["echoed"] = True
        except Exception as exc:  # pragma: no cover - defensive
            _log(f"server echo failed: {exc}")
        if state["remote_identity_hash"] is not None:
            done.set()

    def on_remote_identified(link, remote_identity):
        state["remote_identity_hash"] = remote_identity.hash.hex()
        _log(f"server: remote identified as {state['remote_identity_hash']}")
        if state["received"] is not None:
            done.set()

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
        RNS.Packet(link, payload).send()

    link = RNS.Link(destination, established_callback=on_link_established)

    # 2. Wait for link + echo.
    while time.time() < deadline and not echo_event.is_set():
        echo_event.wait(timeout=1.0)

    result["link_established"] = link_state["active"]
    result["echo_received"] = echo_event.is_set()
    result["echo_matches"] = echo["data"] == payload
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
