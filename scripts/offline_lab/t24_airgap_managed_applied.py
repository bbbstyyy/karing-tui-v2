#!/usr/bin/env python3
"""ADR 0149: native network-none real Daemon -> committed generation -> Core.

All traffic remains inside this throwaway container's 127.0.0.1 namespace.
A synthetic SOCKS node exercises selected-in; direct/rule use local echo.
No CN SRS, remote DNS, TUN, user data, online install or release authority.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

import t24_airgap_bootstrap as boot
import t24_airgap_managed_cold_guard as cold
import t24_airgap_loopback_core as loopback

MANAGED_PORTS = (2080, 2081, 2082)
CONTROL_PORT = 3057
MAX_HTTP_BYTES = 64 << 10


def require(ok, message):
    boot.require(ok, message)


def local_document(socks_port):
    """Valid production V1 declaration, but only synthetic local endpoints."""
    require(type(socks_port) is int and 0 < socks_port < 65536,
            "invalid local node port")
    selected = {"kind": "specific_node", "profile_id": "t24", "node_id": "loop"}
    return {
        "schema_version": 1,
        "log_level": "warn",
        "nodes": [{
            "profile_id": "t24", "node_id": "loop", "type": "socks",
            "server": "127.0.0.1", "port": socks_port,
            "socks": {"version": "5", "network": "tcp"},
        }],
        "selection": {"current": {"members": [selected], "default": selected},
                      "custom": []},
        "routing": {"custom": [], "geosite": [], "geoip": [], "acl": [],
                    "final": {"kind": "direct"}},
        "dns": {
            "profiles": [{
                "id": "local-only", "role": "outbound", "transport": "udp",
                "server": "127.0.0.1", "port": 53,
            }],
            "outbound_profile_id": "local-only",
        },
    }


def assert_synthetic_document(doc, local_socks_port):
    require(isinstance(doc, dict) and set(doc) ==
            {"schema_version", "log_level", "nodes", "selection", "routing", "dns"},
            "unexpected declaration fields")
    require(doc["schema_version"] == 1 and doc["log_level"] == "warn",
            "unexpected schema or logging")
    require(len(doc["nodes"]) == 1 and
            doc["nodes"][0] == {
                "profile_id": "t24", "node_id": "loop", "type": "socks",
                "server": "127.0.0.1", "port": local_socks_port,
                "socks": {"version": "5", "network": "tcp"},
            }, "remote or privileged node was added")
    require(doc["routing"] == {
        "custom": [], "geosite": [], "geoip": [], "acl": [],
        "final": {"kind": "direct"},
    }, "unlicensed or external route was added")
    require(doc["dns"]["profiles"] == [{
        "id": "local-only", "role": "outbound", "transport": "udp",
        "server": "127.0.0.1", "port": 53,
    }] and doc["dns"]["outbound_profile_id"] == "local-only",
        "external DNS was added")
    require(doc["selection"] == {
        "current": {
            "members": [{"kind": "specific_node",
                         "profile_id": "t24", "node_id": "loop"}],
            "default": {"kind": "specific_node", "profile_id": "t24",
                        "node_id": "loop"},
        },
        "custom": [],
    }, "local selection changed")


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=85):
        super().__init__("unix", timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def unix_json(path, method, route, payload=None, expected=200, timeout=85):
    require(route in ("/v1/declaration", "/v1/declaration/compile",
                      "/v1/declaration/apply", "/v1/status", "/v1/capabilities"),
            "unexpected management API route")
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    require(body is None or len(body) <= 8192, "unbounded test input")
    client = UnixHTTP(path, timeout)
    try:
        client.request(method, route, body=body,
                       headers={"Content-Type": "application/json"} if body else {})
        response = client.getresponse()
        raw = response.read(MAX_HTTP_BYTES + 1)
        require(len(raw) <= MAX_HTTP_BYTES, "unbounded management API response")
        require(response.status == expected, "management API step failed: " + route)
        doc = json.loads(raw)
        require(isinstance(doc, dict), "management response was not an object")
        return doc
    finally:
        client.close()


def committed_snapshot(status, generation, desired, running):
    require(type(status) is dict and status.get("api_version") == "v1",
            "invalid managed status")
    expected = {
        "core_configured": True,
        "core_desired_state": desired,
        "core_state": "running" if running else "stopped",
        "recovery_required": False,
        "config_revision": 1,
        "declaration_revision": 1,
        "applied_generation_id": generation,
    }
    for key, value in expected.items():
        require(type(status.get(key)) is type(value) and status.get(key) == value,
                "committed generation status drift: " + key)
    require(type(generation) is int and generation > 0,
            "invalid committed generation")
    require(status.get("core_circuit_open") is False, "managed Core circuit open")
    pid = status.get("core_pid", 0)
    if running:
        require(type(pid) is int and pid > 0, "managed Core never started")
    else:
        require(pid in (None, 0), "Core PID survived committed stop")
    return pid


def exact_read(sock, n):
    return loopback.exact_read(sock, n)


class LocalSocksNode(socketserver.BaseRequestHandler):
    """Only relay CONNECT for one synthetic echo endpoint inside namespace."""

    def handle(self):
        incoming = self.request
        incoming.settimeout(4)
        try:
            version, count = exact_read(incoming, 2)
            require(version == 5 and 0 < count <= 8, "bad local-node greeting")
            require(b"\x00" in exact_read(incoming, count),
                    "Core did not request no-auth SOCKS")
            incoming.sendall(b"\x05\x00")
            require(exact_read(incoming, 4) == b"\x05\x01\x00\x01",
                    "Core requested nonlocal or unsupported destination")
            address = socket.inet_ntoa(exact_read(incoming, 4))
            port = struct.unpack("!H", exact_read(incoming, 2))[0]
            require(address == "127.0.0.1" and port == self.server.echo_port,
                    "Core attempted to forward to a nonlocal target")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as target:
                target.settimeout(3)
                incoming.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                                 struct.pack("!H", port))
                self.server.calls += 1
                until = time.monotonic() + 4
                while time.monotonic() < until:
                    ready, _, _ = select.select([incoming, target], [], [], 0.3)
                    for source in ready:
                        chunk = source.recv(4096)
                        if not chunk:
                            return
                        (target if source is incoming else incoming).sendall(chunk)
        except (OSError, RuntimeError, ValueError):
            self.server.failed = True


class LocalSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def probe_port(port, echo_port, payload):
    require(port in MANAGED_PORTS and 1 <= len(payload) <= 128,
            "unapproved managed port or message")
    with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(b"\x05\x01\x00")
        require(exact_read(sock, 2) == b"\x05\x00",
                "managed SOCKS greeting refused")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                     struct.pack("!H", echo_port))
        header = exact_read(sock, 4)
        require(header[:3] == b"\x05\x00\x00", "managed SOCKS CONNECT refused")
        if header[3] == 1:
            exact_read(sock, 4)
        elif header[3] == 4:
            exact_read(sock, 16)
        elif header[3] == 3:
            exact_read(sock, exact_read(sock, 1)[0])
        else:
            raise RuntimeError("managed SOCKS reply address type refused")
        exact_read(sock, 2)
        sock.sendall(payload)
        require(exact_read(sock, len(loopback.REPLY_PREFIX) + len(payload)) ==
                loopback.REPLY_PREFIX + payload,
                "managed Core packet round trip failed")


def verify_child(pid, daemon_pid, core_path):
    require(type(pid) is int and pid > 0 and daemon_pid > 0,
            "invalid managed child PID")
    proc = Path("/proc") / str(pid)
    status = (proc / "status").read_text(encoding="ascii")
    pairs = [line.split(None, 1) for line in status.splitlines()
             if line.startswith(("PPid:", "Uid:"))]
    values = {key: value.strip() for key, value in pairs}
    require(int(values["PPid:"]) == daemon_pid,
            "Core PID was not a direct child of managed Daemon")
    require(int(values["Uid:"].split()[0]) == os.geteuid(),
            "Core child elevated UID")
    require(os.readlink(proc / "exe") == core_path,
            "Core child executable differs from approved binary")


def wait_status(app, env, expected_state, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            doc = json.loads(boot.checked([app, "status", "--json"], env, 3))
            if doc.get("core_state") == expected_state:
                return doc
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
        time.sleep(0.12)
    raise RuntimeError("managed Core never reached expected state")


def verify_stopped_ports():
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            cold.no_proxy_listener()
            return
        except RuntimeError:
            time.sleep(0.12)
    raise RuntimeError("managed Core ports stayed open after stop")


def run_daemon(app, core, root, env, work):
    logfile = root / "managed-applied.log"
    with logfile.open("ab") as logs:
        process = subprocess.Popen([app, "daemon", "run"], env=env,
                                   stdin=subprocess.DEVNULL, stdout=logs,
                                   stderr=logs)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                require(process.poll() is None,
                        "managed Daemon exited before readiness")
                try:
                    current = json.loads(boot.checked(
                        [app, "status", "--json"], env, timeout=3))
                    if current.get("core_configured") is True:
                        break
                except (OSError, RuntimeError, ValueError,
                        subprocess.SubprocessError):
                    pass
                time.sleep(0.12)
            else:
                raise RuntimeError("managed Daemon readiness timed out")
            return work(process, Path(env["XDG_RUNTIME_DIR"]) /
                        "karing-tui-v2" / "daemon.sock", current)
        finally:
            if process.poll() is None:
                # Do NOT kill a running managed Core without a durable stop.
                process.send_signal(signal.SIGTERM)
            try:
                exited = process.wait(timeout=15)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("managed Daemon did not stop cleanly") from exc
            require(exited == 0, "managed Daemon exited with error")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=boot.MACHINES)
    parser.add_argument("--app", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        boot.ensure_airgap(args.arch)
        require(Path(args.app).is_absolute() and os.access(args.app, os.X_OK),
                "native management executable missing")
        core = Path(args.core)
        require(core.is_absolute(), "Core path must be absolute")
        cold.hash_pinned_core(core, args.core_sha256)
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="t24-applied-", dir="/work") as temp:
            root = Path(temp)
            env = cold.fresh_env(root, args.core)
            with loopback.LoopbackServer(("127.0.0.1", 0),
                                         loopback.LoopbackResponder) as echo:
                echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
                echo_thread.start()
                with LocalSocksServer(("127.0.0.1", 0), LocalSocksNode) as node:
                    node.echo_port = echo.server_address[1]
                    node.calls = 0
                    node.failed = False
                    node_thread = threading.Thread(target=node.serve_forever, daemon=True)
                    node_thread.start()
                    try:
                        document = local_document(node.server_address[1])
                        assert_synthetic_document(document, node.server_address[1])
                        expected_sha = None

                        def first(daemon, sock, initial):
                            nonlocal expected_sha
                            cold.configured_status(initial)
                            cold.configured_caps(unix_json(sock, "GET", "/v1/capabilities"))
                            request = {
                                "expected_revision": 0, "source": "lab:t24-synthetic",
                                "document": document,
                            }
                            committed = unix_json(sock, "POST", "/v1/declaration",
                                                  request, expected=201)
                            revision = committed.get("revision")
                            require(type(revision) is int and revision == 1,
                                    "synthetic declaration was not committed")
                            expected_sha = committed.get("sha256")
                            require(isinstance(expected_sha, str) and
                                    len(expected_sha) == 64,
                                    "declaration SHA missing")
                            compiled = unix_json(sock, "POST", "/v1/declaration/compile",
                                                 {"revision": revision})
                            require(compiled.get("rule_set_count") == 0 and
                                    compiled.get("declaration_sha256") == expected_sha,
                                    "synthetic compile used a ruleset or wrong declaration")
                            applied = unix_json(sock, "POST", "/v1/declaration/apply", {
                                "declaration_revision": 1,
                                "expected_config_revision": 0,
                            }, timeout=85)
                            generation = applied.get("generation_id")
                            require(type(generation) is int and generation > 0 and
                                    applied.get("target_config_revision") == 1 and
                                    applied.get("config_sha256") == compiled.get("config_sha256") and
                                    applied.get("declaration_sha256") == expected_sha,
                                    "committed generation did not bind original compiler receipt")
                            status = wait_status(args.app, env, "stopped")
                            committed_snapshot(status, generation, "stopped", False)
                            boot.checked([args.app, "core", "start"], env, timeout=22)
                            running = wait_status(args.app, env, "running")
                            pid = committed_snapshot(running, generation, "running", True)
                            verify_child(pid, daemon.pid, args.core)
                            for port in MANAGED_PORTS:
                                probe_port(port, echo.server_address[1],
                                           b"managed-first-" + str(port).encode())
                            require(node.calls >= 1 and not node.failed,
                                    "selected-in did not use local synthetic SOCKS node")
                            boot.checked([args.app, "core", "stop"], env, timeout=20)
                            stopped = wait_status(args.app, env, "stopped")
                            committed_snapshot(stopped, generation, "stopped", False)
                            verify_stopped_ports()
                            return generation

                        generation = run_daemon(args.app, args.core, root, env, first)
                        verify_stopped_ports()
                        require(node.calls >= 1 and not node.failed,
                                "synthetic selected node failed")

                        def restart(daemon, sock, initial):
                            committed_snapshot(initial, generation, "stopped", False)
                            cold.configured_caps(unix_json(
                                sock, "GET", "/v1/capabilities"))
                            boot.checked([args.app, "core", "start"], env, timeout=22)
                            running = wait_status(args.app, env, "running")
                            pid = committed_snapshot(running, generation, "running", True)
                            verify_child(pid, daemon.pid, args.core)
                            for port in MANAGED_PORTS:
                                probe_port(port, echo.server_address[1],
                                           b"managed-restart-" + str(port).encode())
                            boot.checked([args.app, "core", "stop"], env, timeout=20)
                            stopped = wait_status(args.app, env, "stopped")
                            committed_snapshot(stopped, generation, "stopped", False)
                            verify_stopped_ports()

                        run_daemon(args.app, args.core, root, env, restart)
                        require(node.calls >= 2 and not node.failed,
                                "synthetic selected proxy was not used on both starts")
                        cold.hash_pinned_core(core, args.core_sha256)
                    finally:
                        node.shutdown()
                        node_thread.join(timeout=5)
                        echo.shutdown()
                        echo_thread.join(timeout=5)
        print("T24_AIRGAP_DAEMON_COMMITTED_CORE_LOOPBACK=ok")
        print("T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false")
        print("T24_OFFLINE_DISTRIBUTION_OR_RESTORE_APPROVED=false")
        return 0
    except (OSError, RuntimeError, ValueError, KeyError,
            subprocess.SubprocessError, http.client.HTTPException):
        print("T24_AIRGAP_DAEMON_COMMITTED_CORE_LOOPBACK=refused",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
