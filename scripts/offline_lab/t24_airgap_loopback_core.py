#!/usr/bin/env python3
"""T24 PARTIAL: real Core loopback-only SOCKS data plane in a network-none container.

Run only after approved Core checksum/native build, in non-root Linux Docker
--network none with no effective capabilities. This never uses CN rule data,
remote addresses, host networking, TUN, DNS or production user credentials.
Success is NOT CN offline routing, a distributable bundle or full T24.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

import t24_airgap_bootstrap as bootstrap

CONTROL = ("127.0.0.1", 29090)
PROXY_PORTS = (28080, 28081, 28082)
SECRET = "isolated-fake-secret"
REPLY_PREFIX = b"T24-local-only:"


class LoopbackResponder(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        payload = self.request.recv(256)
        if payload:
            self.request.sendall(REPLY_PREFIX + payload)


class LoopbackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def require(condition, message):
    bootstrap.require(condition, message)


def exact_read(sock, n):
    data = bytearray()
    while len(data) < n:
        piece = sock.recv(n - len(data))
        require(bool(piece), "unexpected truncated SOCKS5 response")
        data.extend(piece)
    return bytes(data)


def connect_local_socks(proxy_port, target_port, payload):
    """Complete a real SOCKS5 TCP CONNECT through the pinned local Core."""
    require(proxy_port in PROXY_PORTS, "unapproved local proxy port")
    require(isinstance(target_port, int) and 0 < target_port < 65536,
            "invalid local test destination port")
    require(isinstance(payload, bytes) and 1 <= len(payload) <= 128,
            "invalid local test payload")
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as conn:
        conn.settimeout(3)
        conn.sendall(b"\x05\x01\x00")
        require(exact_read(conn, 2) == b"\x05\x00",
                "SOCKS5 no-auth handshake was rejected")
        conn.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                     struct.pack("!H", target_port))
        header = exact_read(conn, 4)
        require(header[:3] == b"\x05\x00\x00",
                "SOCKS5 TCP CONNECT failed for loopback target")
        atyp = header[3]
        if atyp == 1:
            exact_read(conn, 4)
        elif atyp == 4:
            exact_read(conn, 16)
        elif atyp == 3:
            exact_read(conn, exact_read(conn, 1)[0])
        else:
            raise RuntimeError("unexpected SOCKS5 bound-address type")
        exact_read(conn, 2)
        conn.sendall(payload)
        require(exact_read(conn, len(REPLY_PREFIX) + len(payload)) ==
                REPLY_PREFIX + payload,
                "proxy traffic did not reach local echo server intact")


def api_get_version(authorized):
    conn = http.client.HTTPConnection(CONTROL[0], CONTROL[1], timeout=2)
    try:
        headers = {"Authorization": "Bearer " + SECRET} if authorized else {}
        conn.request("GET", "/version", headers=headers)
        response = conn.getresponse()
        body = response.read(4096)
        require(len(body) < 4096, "unbounded local API response")
        return response.status, body
    finally:
        conn.close()


def check_local_core_api(expected_version):
    status, _ = api_get_version(False)
    require(status == 401, "unauthenticated Core API was not denied")
    status, raw = api_get_version(True)
    require(status == 200, "authenticated Core API unavailable")
    doc = json.loads(raw)
    require(isinstance(doc, dict) and
            doc.get("version") == "sing-box " + expected_version and
            doc.get("premium") is True and doc.get("meta") is True,
            "approved local Core API identity mismatch")


def require_inert_loopback_config(path):
    config = json.loads(path.read_text(encoding="ascii"))
    require(set(config) == {"log", "inbounds", "outbounds", "route", "experimental"},
            "unexpected Core network/config section")
    require({(v.get("tag"), v.get("listen"), v.get("listen_port"),
              v.get("set_system_proxy"), v.get("type"))
             for v in config["inbounds"]} ==
            {("rule-in", "127.0.0.1", 28080, False, "mixed"),
             ("direct-in", "127.0.0.1", 28081, False, "mixed"),
             ("selected-in", "127.0.0.1", 28082, False, "mixed")},
            "Core inbound configuration drift")
    require({v.get("type") for v in config["outbounds"]} ==
            {"direct", "block", "selector"} and
            config["route"].get("final") == "direct",
            "unapproved network or default route")
    require("dns" not in config and "tun" not in json.dumps(config).lower() and
            "rule_set" not in json.dumps(config).lower() and
            "http://" not in json.dumps(config).lower() and
            "https://" not in json.dumps(config).lower(),
            "config could require external resources or privileged routing")
    require(config["experimental"]["clash_api"]["external_controller"] ==
            "127.0.0.1:29090" and
            config["experimental"]["clash_api"]["secret"] == SECRET,
            "Core control endpoint is not private and expected")


def run_local_core(core, root, env, expected_version):
    log_file = root / "core-loopback.log"
    with LoopbackServer(("127.0.0.1", 0), LoopbackResponder) as responder:
        listener_port = responder.server_address[1]
        server_thread = threading.Thread(target=responder.serve_forever,
                                         name="t24-local-loopback", daemon=True)
        server_thread.start()
        with log_file.open("ab") as output:
            process = subprocess.Popen(
                [core, "run", "-c", str(root / "core-check.json")],
                env=env, stdin=subprocess.DEVNULL, stdout=output,
                stderr=output)
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    require(process.poll() is None,
                            "approved Core exited before local readiness")
                    try:
                        status, _ = api_get_version(False)
                        if status == 401:
                            break
                    except (ConnectionError, TimeoutError, OSError,
                            http.client.HTTPException):
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Core loopback API readiness timeout")

                check_local_core_api(expected_version)
                for port in PROXY_PORTS:
                    payload = b"offline-" + str(port).encode("ascii")
                    connect_local_socks(port, listener_port, payload)
                require(process.poll() is None,
                        "Core exited during local proxy test")
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                try:
                    code = process.wait(timeout=12)
                except subprocess.TimeoutExpired as exc:
                    process.kill()
                    process.wait(timeout=5)
                    raise RuntimeError("Core did not exit on SIGTERM") from exc
                responder.shutdown()
                server_thread.join(timeout=4)
                require(code == 0, "Core did not stop cleanly")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=bootstrap.MACHINES)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-version", required=True)
    args = parser.parse_args(argv)
    try:
        bootstrap.ensure_airgap(args.arch)
        executable = Path(args.core)
        require(executable.is_absolute() and executable.is_file() and
                os.access(executable, os.X_OK), "approved Core executable unavailable")
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="t24-core-loopback-", dir="/work") as temp:
            root = Path(temp)
            env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(root),
                "XDG_STATE_HOME": str(root),
                "XDG_CACHE_HOME": str(root),
                "LANG": "C.UTF-8",
            }
            bootstrap.verify_core(args.core, args.core_version, root, env)
            require_inert_loopback_config(root / "core-check.json")
            run_local_core(args.core, root, env, args.core_version)
        print("T24_AIRGAP_LOCAL_CORE_SOCKS5=ok")
        print("T24_REMOTE_DNS_OR_CN_ROUTING_VERIFIED=false")
        print("T24_OFFLINE_LICENSE_AND_RELEASE_APPROVED=false")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            http.client.HTTPException):
        # Do not emit raw Core logs, stack traces, paths, URLs, or credentials.
        print("T24_AIRGAP_LOCAL_CORE_SOCKS5=refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
