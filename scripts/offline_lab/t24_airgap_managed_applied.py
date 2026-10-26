#!/usr/bin/env python3
"""ADR 0149: native network-none real Daemon -> committed generation -> Core.

All traffic remains inside this throwaway container's 127.0.0.1 namespace.
A synthetic SOCKS node exercises selected-in; direct/rule use local echo.
No CN SRS, remote DNS, TUN, user data, online install or release authority.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
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


def assert_staged_document(doc, local_socks_port):
    """A second revision may change logging only, never the network envelope."""
    require(isinstance(doc, dict) and doc.get("log_level") == "error",
            "unapproved staged revision")
    original = dict(doc)
    original["log_level"] = "warn"
    assert_synthetic_document(original, local_socks_port)


def staged_document(source, local_socks_port):
    assert_synthetic_document(source, local_socks_port)
    result = json.loads(json.dumps(source))
    result["log_level"] = "error"
    assert_staged_document(result, local_socks_port)
    return result


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=85):
        super().__init__("unix", timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def unix_json(path, method, route, payload=None, expected=200, timeout=85):
    require(route in ("/v1/declaration", "/v1/declaration/current",
                      "/v1/declaration/compile", "/v1/declaration/apply",
                      "/v1/status", "/v1/capabilities"),
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


def committed_snapshot(status, generation, desired, running,
                       declaration_revision=1, config_revision=1):
    require(type(status) is dict and status.get("api_version") == "v1",
            "invalid managed status")
    expected = {
        "core_configured": True,
        "core_desired_state": desired,
        "core_state": "running" if running else "stopped",
        "recovery_required": False,
        "config_revision": config_revision,
        "declaration_revision": declaration_revision,
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


def assert_unapplied_core_unchanged(status, generation, pid, declaration_revision):
    require(type(declaration_revision) is int and declaration_revision in (1, 2),
            "unexpected synthetic declaration head")
    require(committed_snapshot(status, generation, "running", True,
                               declaration_revision) == pid,
            "staged revision restarted or replaced the running Core")
    require(status.get("last_known_good_generation_id") == generation,
            "staged revision replaced last-known-good generation")
    require(status.get("active_operation") in ("", None),
            "staged revision left a pending Core operation")


def stage_and_reject_stale_apply(sock, generation, pid, source,
                                 local_socks_port, original_declaration_sha,
                                 original_config_sha, echo_port, node):
    """Stage revision 2 but *never* activate it; stale CAS must not stop Core."""
    current = unix_json(sock, "GET", "/v1/declaration/current")
    require(current.get("revision") == 1 and
            current.get("sha256") == original_declaration_sha,
            "initial declaration head drifted before staging")
    assert_unapplied_core_unchanged(
        unix_json(sock, "GET", "/v1/status"), generation, pid, 1)

    # Untrusted/unsupported privileged fields must fail before any commit.
    invalid = json.loads(json.dumps(source))
    invalid["tun"] = True
    rejected = unix_json(sock, "POST", "/v1/declaration", {
        "expected_revision": 1, "source": "lab:t24-invalid-rejected",
        "document": invalid,
    }, expected=400, timeout=10)
    require(isinstance(rejected.get("error"), str) and rejected["error"],
            "invalid candidate did not return a typed refusal")
    unchanged = unix_json(sock, "GET", "/v1/declaration/current")
    require(unchanged.get("revision") == 1 and
            unchanged.get("sha256") == original_declaration_sha,
            "rejected privileged field advanced declaration revision")

    candidate = staged_document(source, local_socks_port)
    revision = unix_json(sock, "POST", "/v1/declaration", {
        "expected_revision": 1, "source": "lab:t24-unapplied-only",
        "document": candidate,
    }, expected=201, timeout=10)
    next_sha = revision.get("sha256")
    require(type(revision.get("revision")) is int and revision["revision"] == 2
            and isinstance(next_sha, str) and len(next_sha) == 64
            and next_sha != original_declaration_sha,
            "staged declaration revision and digest were not advanced")
    head = unix_json(sock, "GET", "/v1/declaration/current")
    require(head.get("revision") == 2 and head.get("sha256") == next_sha
            and head.get("document") == candidate,
            "staged declaration was not durable or changed its contents")

    preview = unix_json(sock, "POST", "/v1/declaration/compile",
                        {"revision": 2}, timeout=20)
    require(preview.get("revision") == 2
            and preview.get("declaration_sha256") == next_sha
            and preview.get("rule_set_count") == 0
            and isinstance(preview.get("config_sha256"), str)
            and len(preview["config_sha256"]) == 64
            and preview["config_sha256"] != original_config_sha,
            "unapplied revision did not compile independently")

    conflict = unix_json(sock, "POST", "/v1/declaration/apply", {
        "declaration_revision": 2,
        "expected_config_revision": 0,
    }, expected=409, timeout=20)
    require(isinstance(conflict.get("error"), str) and conflict["error"],
            "stale config revision was not explicitly rejected")
    assert_unapplied_core_unchanged(
        unix_json(sock, "GET", "/v1/status"), generation, pid, 2)
    probe_isolated_routes(echo_port, b"staged-not-applied-", node)
    assert_unapplied_core_unchanged(
        unix_json(sock, "GET", "/v1/status"), generation, pid, 2)
    return next_sha, preview["config_sha256"]


def assert_promoted_core(status, old_generation, generation, old_pid,
                         running):
    """Ensure the persisted new generation, LKG and running intent agree."""
    require(type(old_generation) is int and old_generation > 0 and
            type(generation) is int and generation > old_generation,
            "promoted generation must differ from old applied generation")
    pid = committed_snapshot(status, generation,
                             "running" if running else "stopped", running,
                             declaration_revision=2, config_revision=2)
    require(status.get("last_known_good_generation_id") == generation and
            status.get("active_operation") in (None, ""),
            "promoted generation did not commit LKG or left a pending operation")
    if running and old_pid is not None:
        require(type(old_pid) is int and old_pid > 0 and pid != old_pid,
                "generation activation never replaced old Core process")
    return pid


def promote_staged_generation(sock, app, env, daemon_pid, core_path,
                              old_generation, old_pid, staged_sha,
                              staged_config_sha, echo_port, node):
    """Apply exactly revision 2 under a valid CAS while real Core is running."""
    require(type(staged_sha) is str and len(staged_sha) == 64 and
            type(staged_config_sha) is str and len(staged_config_sha) == 64,
            "invalid staged declaration/config identity")
    assert_unapplied_core_unchanged(
        unix_json(sock, "GET", "/v1/status"), old_generation, old_pid, 2)
    head = unix_json(sock, "GET", "/v1/declaration/current")
    require(head.get("revision") == 2 and head.get("sha256") == staged_sha,
            "staged declaration changed before approved apply")
    preview = unix_json(sock, "POST", "/v1/declaration/compile",
                        {"revision": 2}, timeout=20)
    require(preview.get("revision") == 2 and
            preview.get("declaration_sha256") == staged_sha and
            preview.get("config_sha256") == staged_config_sha and
            preview.get("rule_set_count") == 0,
            "staged native config drifted before approved apply")
    receipt = unix_json(sock, "POST", "/v1/declaration/apply", {
        "declaration_revision": 2, "expected_config_revision": 1,
    }, timeout=85)
    generation = receipt.get("generation_id")
    require(type(generation) is int and generation > old_generation and
            receipt.get("base_config_revision") == 1 and
            receipt.get("target_config_revision") == 2 and
            receipt.get("declaration_revision") == 2 and
            receipt.get("declaration_sha256") == staged_sha and
            receipt.get("config_sha256") == staged_config_sha and
            type(receipt.get("attempt_id")) is int and receipt["attempt_id"] > 0,
            "valid CAS did not produce verified generation 2")
    status = wait_status(app, env, "running")
    pid = assert_promoted_core(status, old_generation, generation, old_pid, True)
    verify_child(pid, daemon_pid, core_path)
    probe_isolated_routes(echo_port, b"promoted-live-", node)
    require(assert_promoted_core(unix_json(sock, "GET", "/v1/status"),
                                 old_generation, generation, old_pid, True) == pid,
            "promoted Core restarted while forwarding local traffic")
    return generation, pid


def wait_restarted_promoted_core(sock, generation, promoted_generation,
                                 dead_pid, timeout=25):
    """Watch a single recorded crash; never treat a transient old PID as recovery."""
    require(type(dead_pid) is int and dead_pid > 0 and
            type(timeout) is int and 0 < timeout <= 30,
            "unbounded or invalid managed crash-restart wait")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = unix_json(sock, "GET", "/v1/status", timeout=5)
        require(current.get("core_circuit_open") is False and
                current.get("recovery_required") is False,
                "managed Core opened circuit or required recovery after one crash")
        require(current.get("config_revision") == 2 and
                current.get("declaration_revision") == 2 and
                current.get("applied_generation_id") == promoted_generation and
                current.get("last_known_good_generation_id") == promoted_generation and
                current.get("core_desired_state") == "running",
                "crash reset applied generation/LKG/revision or running intent")
        pid = current.get("core_pid")
        if (current.get("core_state") == "running" and
                type(pid) is int and pid > 0 and pid != dead_pid):
            recovered = assert_promoted_core(
                current, generation, promoted_generation, dead_pid, True)
            require(recovered == pid and
                    type(current.get("core_consecutive_failures")) is int and
                    current["core_consecutive_failures"] >= 1,
                    "new Core PID lacks supervised failure accounting")
            return pid
        time.sleep(0.15)
    raise RuntimeError("promoted managed Core failed to restart after one crash")


def probe_supervised_crash_recovery(sock, daemon_pid, core_path,
                                    old_generation, promoted_generation,
                                    running_pid, echo_port, node):
    """SIGKILL only the exact pinned same-UID daemon child, using a pidfd."""
    require(type(running_pid) is int and running_pid > 1 and
            type(daemon_pid) is int and daemon_pid > 1 and
            running_pid != daemon_pid,
            "unsafe Core crash injection PID")
    before_pid = assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, None, True)
    require(before_pid == running_pid,
            "stale Core PID before fault injection; refuse signal")
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "kernel/Python pidfd signaling unavailable; refuse unsafe PID kill")
    pidfd = os.pidfd_open(running_pid)
    try:
        verify_child(running_pid, daemon_pid, core_path)
        # A pidfd prevents PID reuse, but must still be bound to the *current*
        # managed generation. Recheck the actual daemon status after opening.
        sampled_pid = assert_promoted_core(
            unix_json(sock, "GET", "/v1/status"),
            old_generation, promoted_generation, None, True)
        require(sampled_pid == running_pid,
                "managed Core PID changed after pidfd open; refuse signal")
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    finally:
        os.close(pidfd)
    restarted_pid = wait_restarted_promoted_core(
        sock, old_generation, promoted_generation, running_pid)
    verify_child(restarted_pid, daemon_pid, core_path)
    probe_isolated_routes(echo_port, b"promoted-crash-recovered-", node)
    probe_isolated_failure(echo_port, b"failed-after-crash-", node)
    require(assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, running_pid, True) == restarted_pid,
        "recovered promoted Core restarted after Selected failure")
    probe_isolated_routes(echo_port, b"restored-after-crash-", node)
    require(assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, running_pid, True) == restarted_pid,
        "recovered Core PID changed during healthy forwarding")
    return restarted_pid



def probe_held_crash_recovery(sock, daemon_pid, core_path,
                              old_generation, promoted_generation,
                              running_pid, echo_port, node, stage_hook=None):
    """Crash one verified Core with all three SOCKS5 TCP tunnels established.

    The pre-existing pidfd-bound crash and recovery path still owns the
    only SIGKILL; this wrapper may not signal an unverified or replaced PID.
    """
    require(stage_hook is None or callable(stage_hook),
            "invalid crash diagnostic hook")
    def mark(stage):
        if stage_hook is not None:
            stage_hook(stage)
    mark("crash-held-preflight")
    require(type(running_pid) is int and running_pid > 1 and
            type(echo_port) is int and 0 < echo_port < 65536 and
            type(node.calls) is int and node.calls >= 0 and
            type(node.rejections) is int and node.rejections >= 0 and
            not node.failed and not node.reject_connections,
            "invalid pre-crash held-session fixture")
    before = assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, None, True)
    require(before == running_pid,
            "Core PID or generation drifted before opening held crash tunnels")
    baseline_calls, baseline_denials = node.calls, node.rejections
    with ExitStack() as stack:
        held = []
        for port in MANAGED_PORTS:
            mark("crash-held-open-%d" % port)
            payload = b"held-crash-" + str(port).encode("ascii")
            held.append(stack.enter_context(
                open_held_socks_echo(port, echo_port, payload)))
            require(node.calls == baseline_calls + (1 if port == 2082 else 0)
                    and node.rejections == baseline_denials and not node.failed,
                    "held crash tunnel crossed Selected or skipped its node")

        # Refuse to kill an unrelated, replaced or new unapproved Core even
        # if all three old listening sockets still appear reachable.
        mark("crash-held-pid-check")
        require(assert_promoted_core(
            unix_json(sock, "GET", "/v1/status"),
            old_generation, promoted_generation, None, True) == running_pid,
            "Core identity drifted while crash tunnels were established")
        mark("crash-held-supervised-recovery")
        restarted = probe_supervised_crash_recovery(
            sock, daemon_pid, core_path, old_generation, promoted_generation,
            running_pid, echo_port, node)
        # Do not mistake a new healthy Core listener for an old tunnel that
        # survived the killed process. Every old stream must terminate.
        mark("crash-held-sockets-closed")
        for conn in held:
            assert_held_session_closed(conn)
        mark("crash-held-node-audit")
        require(node.calls == baseline_calls + 3 and
                node.rejections > baseline_denials and
                not node.failed and not node.reject_connections,
                "held crash, recovery or Selected route changed the audit")
        return restarted


def exact_read(sock, n):
    return loopback.exact_read(sock, n)


def is_post_echo_peer_reset(exc, forwarded_reply):
    """Only completed local test relays may end with an ordinary TCP reset.

    A failed handshake, failed CONNECT, no returned echo bytes, timeout or
    other I/O error is never excused. The client independently checks the
    entire expected echo before a successful test is recorded.
    """
    return (type(forwarded_reply) is bool and forwarded_reply
            and type(exc) in (ConnectionResetError, ConnectionAbortedError,
                              BrokenPipeError))


class LocalSocksNode(socketserver.BaseRequestHandler):
    """Only relay CONNECT for one synthetic echo endpoint inside namespace."""

    def handle(self):
        incoming = self.request
        incoming.settimeout(4)
        forwarded_reply = False
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
            if self.server.reject_connections:
                # A real SOCKS5 CONNECT failure, not a closed test listener:
                # the managed Core must not fall back to an unrequested path.
                with self.server.counter_lock:
                    self.server.rejections += 1
                incoming.sendall(b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00")
                return
            with socket.create_connection(("127.0.0.1", port), timeout=3) as target:
                target.settimeout(3)
                incoming.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                                 struct.pack("!H", port))
                with self.server.counter_lock:
                    self.server.calls += 1
                until = time.monotonic() + 4
                audit_prefix = bytearray()
                audited = False
                while time.monotonic() < until:
                    ready, _, _ = select.select([incoming, target], [], [], 0.3)
                    for source in ready:
                        chunk = source.recv(4096)
                        if not chunk:
                            return
                        # The 32-byte test-only parallel payload identifies
                        # its inbound even if TCP divides the bytes across reads.
                        if source is incoming and not audited:
                            audit_prefix.extend(chunk[:32 - len(audit_prefix)])
                            if (len(audit_prefix) >= 9 and
                                    not audit_prefix.startswith(b"parallel-")):
                                audited = True
                            elif len(audit_prefix) == 32:
                                with self.server.counter_lock:
                                    self.server.parallel_payloads.append(
                                        bytes(audit_prefix))
                                audited = True
                        if source is incoming:
                            target.sendall(chunk)
                        else:
                            incoming.sendall(chunk)
                            # Only after a successful application reply has
                            # crossed the synthetic relay can a peer reset be
                            # treated as a normal completed-session close.
                            forwarded_reply = True
        except (OSError, RuntimeError, ValueError) as exc:
            if not is_post_echo_peer_reset(exc, forwarded_reply):
                self.server.failed = True


class LocalSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.calls = 0
        self.rejections = 0
        self.reject_connections = False
        self.failed = False
        self.counter_lock = threading.Lock()
        self.parallel_payloads = []


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





def open_held_socks_echo(port, echo_port, payload):
    """Open one *live* local SOCKS5 echo stream; caller owns socket closure."""
    require(type(port) is int and port in MANAGED_PORTS and
            type(echo_port) is int and 0 < echo_port < 65536 and
            type(payload) is bytes and 1 <= len(payload) <= 128,
            "invalid held local SOCKS5 session")
    conn = socket.create_connection(("127.0.0.1", port), timeout=4)
    try:
        conn.settimeout(4)
        conn.sendall(b"\x05\x01\x00")
        require(exact_read(conn, 2) == b"\x05\x00",
                "held SOCKS5 greeting was refused")
        conn.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                     struct.pack("!H", echo_port))
        header = exact_read(conn, 4)
        require(header[:3] == b"\x05\x00\x00",
                "held SOCKS5 CONNECT was refused")
        if header[3] == 1:
            exact_read(conn, 4)
        elif header[3] == 4:
            exact_read(conn, 16)
        elif header[3] == 3:
            exact_read(conn, exact_read(conn, 1)[0])
        else:
            raise RuntimeError("held SOCKS5 reply address type refused")
        exact_read(conn, 2)
        conn.sendall(payload)
        require(exact_read(conn, len(loopback.REPLY_PREFIX) + len(payload)) ==
                loopback.REPLY_PREFIX + payload,
                "held SOCKS5 stream failed initial exact echo")
        return conn
    except BaseException:
        conn.close()
        raise


def assert_held_session_closed(conn):
    """An explicit stop must close each established Core-owned TCP stream."""
    conn.settimeout(3)
    try:
        received = conn.recv(1)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return
    require(received == b"",
            "stopped Core still relayed data on a held SOCKS5 connection")


def stop_core_with_held_tunnels(app, env, sock, echo_port, node,
                                old_generation, promoted_generation, expected_pid):
    """Stop exactly the managed generation owning three held TCP streams."""
    require(type(echo_port) is int and 0 < echo_port < 65536 and
            type(node.calls) is int and node.calls >= 0 and
            not node.failed and not node.reject_connections,
            "invalid or unhealthy held-session fixture")
    require(type(expected_pid) is int and expected_pid > 0 and
            assert_promoted_core(unix_json(sock, "GET", "/v1/status"),
                                 old_generation, promoted_generation,
                                 None, True) == expected_pid,
            "held-session stop began on a stale Core PID or generation")
    baseline = node.calls
    with ExitStack() as stack:
        held = []
        for port in MANAGED_PORTS:
            payload = b"held-stop-" + str(port).encode("ascii")
            held.append(stack.enter_context(
                open_held_socks_echo(port, echo_port, payload)))
            require(node.calls == baseline + (1 if port == 2082 else 0)
                    and not node.failed,
                    "held Rule/Direct used Selected node or Selected bypassed it")
        require(assert_promoted_core(
            unix_json(sock, "GET", "/v1/status"),
            old_generation, promoted_generation, None, True) == expected_pid,
            "Core changed while test clients were establishing held sessions")
        boot.checked([app, "core", "stop"], env, timeout=20)
        stopped = wait_status(app, env, "stopped")
        for conn in held:
            assert_held_session_closed(conn)
        require(node.calls == baseline + 1 and not node.failed,
                "held sessions changed route count during stop")
        return stopped



def parallel_probe_payload(index, iteration, port):
    """Fixed 32-byte audit tag; synthetic node can reconstruct split TCP reads."""
    require(type(index) is int and 0 <= index < 6 and
            type(iteration) is int and iteration in (0, 1) and
            type(port) is int and port in MANAGED_PORTS,
            "invalid parallel probe payload identity")
    payload = ("parallel-" + str(index) + "-" +
               str(iteration) + "-").encode("ascii").ljust(28, b"_")
    return payload + str(port).encode("ascii")


def probe_bounded_parallel_routes(echo_port, node):
    """Six concurrent localhost clients; verify Selected's exact payload tags."""
    require(type(echo_port) is int and 0 < echo_port < 65536,
            "invalid parallel-probe echo port")
    require(type(node.calls) is int and node.calls >= 0 and
            type(node.rejections) is int and node.rejections >= 0 and
            type(node.parallel_payloads) is list and
            not node.failed and not node.reject_connections,
            "parallel-probe synthetic node was not healthy")
    original_calls, original_denials = node.calls, node.rejections
    original_tags = len(node.parallel_payloads)
    barrier = threading.Barrier(6)

    def worker(index):
        port = MANAGED_PORTS[index % len(MANAGED_PORTS)]
        barrier.wait(timeout=8)
        for iteration in range(2):
            probe_port(port, echo_port,
                       parallel_probe_payload(index, iteration, port))
        return port

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(worker, index) for index in range(6)]
        completed = [future.result(timeout=40) for future in futures]
    require(all(completed.count(port) == 2 for port in MANAGED_PORTS),
            "parallel inbounds lacked two simultaneous workers")
    # Exactly two Selected workers, each making two successful connections.
    # Rule/Direct must not pass through the Selected synthetic SOCKS node.
    expected_tags = {
        parallel_probe_payload(index, iteration, 2082)
        for index in (2, 5) for iteration in range(2)
    }
    actual_tags = node.parallel_payloads[original_tags:]
    require(node.calls == original_calls + 4 and
            node.rejections == original_denials and not node.failed and
            len(actual_tags) == 4 and set(actual_tags) == expected_tags,
            "parallel Rule/Direct crossed Selected, Selected bypassed, or node failed")
    return len(completed) * 2



def probe_parallel_selected_denials(echo_port, node):
    """Six simultaneous clients: Direct/Rule succeed; Selected fails closed."""
    require(type(echo_port) is int and 0 < echo_port < 65536,
            "invalid parallel failure-probe echo port")
    require(type(node.calls) is int and node.calls >= 0 and
            type(node.rejections) is int and node.rejections >= 0 and
            type(node.parallel_payloads) is list and
            not node.failed and not node.reject_connections,
            "synthetic selected node was unhealthy before parallel refusal")
    accepted, rejected, tags = node.calls, node.rejections, len(node.parallel_payloads)
    barrier = threading.Barrier(6)
    node.reject_connections = True
    try:
        def worker(index):
            port = MANAGED_PORTS[index % len(MANAGED_PORTS)]
            barrier.wait(timeout=8)
            for iteration in range(2):
                if port == 2082:
                    probe_selected_refusal(echo_port)
                else:
                    payload = ("parallel-denied-" + str(index) + "-" +
                               str(iteration) + "-" + str(port)).encode("ascii")
                    probe_port(port, echo_port, payload)
            return port

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(worker, i) for i in range(6)]
            completed = [future.result(timeout=40) for future in futures]
        require(all(completed.count(port) == 2 for port in MANAGED_PORTS),
                "parallel refusal did not complete all expected inbounds")
        # The managed Core may retry a refused upstream, but repeated
        # unbounded retries are not accepted as healthy isolated behavior.
        denial_delta = node.rejections - rejected
        require(node.calls == accepted and len(node.parallel_payloads) == tags
                and 4 <= denial_delta <= 16 and not node.failed,
                "Selected failure bypassed upstream or impaired Rule/Direct")
        return len(completed) * 2
    finally:
        node.reject_connections = False


def probe_isolated_routes(echo_port, prefix, node):
    """Require exactly one local-node dial, from Selected only, per cycle."""
    require(node.calls >= 0 and not node.failed,
            "synthetic SOCKS node unhealthy before route probes")
    prior = node.calls
    for port in MANAGED_PORTS:
        probe_port(port, echo_port, prefix + str(port).encode())
        expected = prior + (1 if port == 2082 else 0)
        require(node.calls == expected and not node.failed,
                "Rule/Direct crossed into Selected or Selected bypassed its node")
    require(node.calls == prior + 1,
            "Selected route did not traverse exactly one local proxy")



def probe_selected_refusal(echo_port):
    """Require a bounded failure, not SOCKS success, on the Selected inbound."""
    require(type(echo_port) is int and 0 < echo_port < 65536,
            "invalid failure-probe target port")
    with socket.create_connection(("127.0.0.1", 2082), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(b"\x05\x01\x00")
        require(exact_read(sock, 2) == b"\x05\x00",
                "Selected SOCKS greeting unavailable during node failure")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                     struct.pack("!H", echo_port))
        reply = bytearray()
        while len(reply) < 2:
            try:
                fragment = sock.recv(2 - len(reply))
            except (ConnectionResetError, ConnectionAbortedError):
                break  # Closing without a success response is fail-closed.
            if not fragment:
                break
            reply.extend(fragment)
        require(not reply or
                (len(reply) == 2 and reply[0] == 5 and reply[1] != 0),
                "Selected returned success or a malformed refusal")


def probe_isolated_failure(echo_port, prefix, node):
    """Block only Selected's local node; Rule and Direct must remain healthy."""
    require(not node.reject_connections and not node.failed,
            "synthetic node was not healthy before the failure")
    accepted, denied = node.calls, node.rejections
    node.reject_connections = True
    try:
        for port in MANAGED_PORTS[:2]:
            probe_port(port, echo_port, prefix + str(port).encode())
            require(node.calls == accepted and node.rejections == denied and
                    not node.failed,
                    "healthy Rule/Direct unexpectedly used failed Selected node")
        probe_selected_refusal(echo_port)
        require(node.rejections > denied and node.calls == accepted and
                not node.failed,
                "Selected failure bypassed node or relayed TCP to echo")
    finally:
        node.reject_connections = False


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


def daemon_fd_count(pid):
    """Count only the same-UID daemon's procfs descriptors, not Core's."""
    require(type(pid) is int and pid > 1, "invalid Daemon FD sample PID")
    count = len(os.listdir("/proc/" + str(pid) + "/fd"))
    require(0 < count < 1024, "unbounded or empty Daemon fd table")
    return count


def assert_cycle_fd_budget(baseline, samples):
    """Three short cycles can catch gross leaks, not establish long soak."""
    require(type(baseline) is int and 0 < baseline < 1024,
            "invalid baseline Daemon FD count")
    require(type(samples) is list and len(samples) == 3 and
            all(type(n) is int and 0 < n < 1024 for n in samples),
            "missing bounded lifecycle samples")
    require(max(samples) <= baseline + 24 and
            max(samples) - min(samples) <= 16,
            "Daemon FD count drifted during short lifecycle smoke")



def reconnect_fd_budget(daemon_before, core_before, daemon_after, core_after):
    """Gross bounded FD drift guard, not a leak-free or long-soak claim."""
    samples = (daemon_before, core_before, daemon_after, core_after)
    require(all(type(sample) is int and 0 < sample < 1024
                for sample in samples), "invalid reconnect FD sample")
    return (daemon_after <= daemon_before + 16 and
            core_after <= core_before + 24)


def owned_core_fd_count(pid, daemon_pid, core_path):
    """Read only the exact pinned, same-UID child Core's procfs fd count."""
    verify_child(pid, daemon_pid, core_path)
    return daemon_fd_count(pid)


def probe_bounded_reconnect_churn(sock, daemon_pid, core_path,
                                   old_generation, promoted_generation,
                                   running_pid, echo_port, node, cycles=24):
    """Reconnect all 3 real localhost inbounds; check unchanged PID and FD."""
    require(type(cycles) is int and 1 <= cycles <= 24 and
            type(running_pid) is int and running_pid > 1 and
            type(echo_port) is int and 0 < echo_port < 65536 and
            type(node.calls) is int and node.calls >= 0 and
            type(node.rejections) is int and node.rejections >= 0 and
            type(node.parallel_payloads) is list and
            not node.failed and not node.reject_connections,
            "invalid reconnect churn precondition")
    require(assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, None, True) == running_pid,
        "reconnect churn began on stale Core or generation")
    daemon_before = daemon_fd_count(daemon_pid)
    core_before = owned_core_fd_count(running_pid, daemon_pid, core_path)
    accepted, denied, parallel_tags = (
        node.calls, node.rejections, len(node.parallel_payloads))
    for index in range(cycles):
        probe_isolated_routes(
            echo_port, ("reconnect-%02d-" % index).encode("ascii"), node)
        require(node.calls == accepted + index + 1 and
                node.rejections == denied and
                len(node.parallel_payloads) == parallel_tags and
                not node.failed and not node.reject_connections,
                "reconnect crossed Selected, bypassed, or changed node health")
        # Check the actual Daemon state during a bounded reconnect burst, not
        # merely at the beginning and after a possibly silent Core restart.
        if (index + 1) % 8 == 0:
            require(assert_promoted_core(
                unix_json(sock, "GET", "/v1/status"),
                old_generation, promoted_generation, None, True) == running_pid,
                "reconnect silently replaced Core or active generation")
    require(assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, None, True) == running_pid,
        "reconnect ended with wrong Core or generation")
    deadline = time.monotonic() + 4
    while True:
        daemon_after = daemon_fd_count(daemon_pid)
        core_after = owned_core_fd_count(running_pid, daemon_pid, core_path)
        if reconnect_fd_budget(daemon_before, core_before,
                               daemon_after, core_after):
            return cycles * len(MANAGED_PORTS)
        if time.monotonic() >= deadline:
            raise RuntimeError("reconnect FD budget did not settle")
        time.sleep(0.12)


def probe_bounded_lifecycle_cycles(app, env, sock, daemon_pid, core_path,
                                   old_generation, promoted_generation,
                                   echo_port, node, stage_hook=None):
    """Three explicit start/stop cycles on unchanged persisted generation 2."""
    require(stage_hook is None or callable(stage_hook),
            "invalid lifecycle diagnostic hook")
    def mark(stage):
        if stage_hook is not None:
            stage_hook(stage)
    mark("held-lifecycle-preflight")
    require(assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, None, False) == 0,
        "short lifecycle experiment began with Core running")
    baseline = daemon_fd_count(daemon_pid)
    samples = []
    for cycle in range(3):
        mark("held-lifecycle-cycle-%d-start" % cycle)
        boot.checked([app, "core", "start"], env, timeout=22)
        running = wait_status(app, env, "running")
        pid = assert_promoted_core(running, old_generation, promoted_generation,
                                   None, True)
        verify_child(pid, daemon_pid, core_path)
        prefix = ("lifecycle-" + str(cycle) + "-").encode()
        mark("held-lifecycle-cycle-%d-routes" % cycle)
        probe_isolated_routes(echo_port, prefix, node)
        if cycle == 1:
            mark("held-lifecycle-cycle-1-selected-refusal")
            probe_isolated_failure(echo_port, b"lifecycle-refusal-", node)
            probe_isolated_routes(echo_port, b"lifecycle-restored-", node)
        if cycle == 2:
            mark("held-lifecycle-cycle-2-parallel")
            require(probe_bounded_parallel_routes(echo_port, node) == 12,
                    "bounded parallel workload did not finish all 12 echoes")
            require(probe_parallel_selected_denials(echo_port, node) == 12,
                    "parallel Selected refusal lost healthy Rule/Direct traffic")
            require(assert_promoted_core(
                unix_json(sock, "GET", "/v1/status"),
                old_generation, promoted_generation, None, True) == pid,
                "parallel Selected refusal unexpectedly restarted Core")
            require(probe_bounded_parallel_routes(echo_port, node) == 12,
                    "parallel Selected upstream did not recover in same Core")
        require(assert_promoted_core(
            unix_json(sock, "GET", "/v1/status"),
            old_generation, promoted_generation, None, True) == pid,
            "short lifecycle traffic unexpectedly replaced running Core")
        mark("held-lifecycle-cycle-%d-stop" % cycle)
        if cycle == 2:
            stopped = stop_core_with_held_tunnels(
                app, env, sock, echo_port, node,
                old_generation, promoted_generation, pid)
        else:
            boot.checked([app, "core", "stop"], env, timeout=20)
            stopped = wait_status(app, env, "stopped")
        mark("held-lifecycle-cycle-%d-stopped-audit" % cycle)
        assert_promoted_core(stopped, old_generation, promoted_generation,
                             None, False)
        verify_stopped_ports()
        samples.append(daemon_fd_count(daemon_pid))
    mark("held-lifecycle-fd-budget")
    assert_cycle_fd_budget(baseline, samples)
    return samples


def probe_restart_after_held_stop(app, env, sock, daemon_pid, core_path,
                                  old_generation, promoted_generation,
                                  echo_port, node, declaration_sha):
    """Explicit restart after held-session stop: old generation never reappears."""
    require(type(echo_port) is int and 0 < echo_port < 65536 and
            isinstance(declaration_sha, str) and len(declaration_sha) == 64
            and type(node.calls) is int and node.calls >= 0
            and type(node.rejections) is int and node.rejections >= 0
            and not node.failed and not node.reject_connections,
            "invalid post-held-stop restart fixture")
    require(assert_promoted_core(
        unix_json(sock, "GET", "/v1/status"),
        old_generation, promoted_generation, None, False) == 0,
        "previously stopped Core resumed without an operator request")
    require(unix_json(sock, "GET", "/v1/declaration/current").get("sha256")
            == declaration_sha,
            "held-stop restart changed the committed declaration head")
    verify_stopped_ports()
    original_calls, original_denials = node.calls, node.rejections
    started = False
    try:
        boot.checked([app, "core", "start"], env, timeout=22)
        started = True
        running = wait_status(app, env, "running")
        pid = assert_promoted_core(
            running, old_generation, promoted_generation, None, True)
        verify_child(pid, daemon_pid, core_path)
        probe_isolated_routes(echo_port, b"after-held-stop-start-", node)
        probe_isolated_failure(echo_port, b"after-held-stop-failed-", node)
        require(assert_promoted_core(
            unix_json(sock, "GET", "/v1/status"),
            old_generation, promoted_generation, None, True) == pid,
            "Selected refusal restarted Core after held-session recovery")
        probe_isolated_routes(echo_port, b"after-held-stop-restored-", node)
        require(assert_promoted_core(
            unix_json(sock, "GET", "/v1/status"),
            old_generation, promoted_generation, None, True) == pid,
            "post-held-stop traffic replaced healthy Core")
        require(node.calls == original_calls + 2 and
                node.rejections > original_denials and
                not node.failed and not node.reject_connections,
                "post-held-stop restart bypassed Selected or failed recovery")
        # This remains inside the same explicit start/stop and finally guard.
        require(probe_bounded_reconnect_churn(
            sock, daemon_pid, core_path, old_generation, promoted_generation,
            pid, echo_port, node) == 72,
            "bounded reconnect smoke did not complete all three inbounds")
        return pid
    finally:
        if started:
            # Even an assertion failure must not leave a live test Core behind.
            boot.checked([app, "core", "stop"], env, timeout=20)
            stopped = wait_status(app, env, "stopped")
            require(assert_promoted_core(
                stopped, old_generation, promoted_generation,
                None, False) == 0,
                "post-held-stop Core did not persist explicit stopped intent")
            verify_stopped_ports()


def verify_stopped_ports():
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            cold.no_proxy_listener()
            return
        except RuntimeError:
            time.sleep(0.12)
    raise RuntimeError("managed Core ports stayed open after stop")



# A strict allow-list: never emit exception strings or daemon output, even
# when a Python or CLI error unexpectedly contains URLs, headers or tokens.
AIRGAP_FAILURE_CODES = {
    "managed Daemon readiness timed out": "daemon-readiness",
    "managed Core never reached expected state": "core-state-timeout",
    "short lifecycle experiment began with Core running": "unexpected-core-running",
    "short lifecycle traffic unexpectedly replaced running Core": "core-identity-drift",
    "Daemon FD count drifted during short lifecycle smoke": "daemon-fd-drift",
    "managed Core ports stayed open after stop": "proxy-listener-open",
    "held sessions changed route count during stop": "held-route-drift",
    "held Rule/Direct used Selected node or Selected bypassed it": "held-route-bypass",
    "Core changed while test clients were establishing held sessions":
        "held-core-identity-drift",
    "stopped Core still relayed data on a held SOCKS5 connection":
        "held-stream-not-closed",
    "parallel Selected refusal unexpectedly restarted Core":
        "parallel-core-restart",
    "short lifecycle restart lost declaration head": "declaration-drift",
    "missing lifecycle FD samples": "missing-fd-samples",
    "invalid lifecycle diagnostic hook": "invalid-stage-hook",
    "invalid crash diagnostic hook": "invalid-crash-stage-hook",
    "managed Daemon reopened Core without stopped intent":
        "daemon-implicit-core-start",
    "Core PID or generation drifted before opening held crash tunnels":
        "crash-held-stale-pid",
    "held crash tunnel crossed Selected or skipped its node":
        "crash-held-route-bypass",
    "Core identity drifted while crash tunnels were established":
        "crash-held-pid-drift",
    "held crash, recovery or Selected route changed the audit":
        "crash-held-node-drift",
    "promoted managed Core failed to restart after one crash":
        "crash-restart-timeout",
    "new Core PID lacks supervised failure accounting":
        "crash-missing-failure-count",
    "stale Core PID before fault injection; refuse signal":
        "crash-stale-pid-refused",
    "managed Core PID changed after pidfd open; refuse signal":
        "crash-pidfd-drift-refused",
    "recovered promoted Core restarted after Selected failure":
        "crash-selected-restarted",
}


def safe_airgap_failure_code(exc):
    """Sanitize diagnostic root cause: fixed labels only, never str(exc)."""
    if type(exc) is not RuntimeError:
        return "unclassified"
    return AIRGAP_FAILURE_CODES.get(str(exc), "unclassified")


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
                except (OSError, RuntimeError, ValueError,
                        subprocess.SubprocessError):
                    time.sleep(0.12)
                    continue
                if current.get("core_configured") is True:
                    # Every native run_daemon call opens an already-stopped
                    # Core, including the first fresh private SQLite. A
                    # configured flag alone can precede journal replay and
                    # stable stop status. Never pass a transitional snapshot
                    # to a strict generation/PID audit callback.
                    require(current.get("core_desired_state") != "running" and
                            current.get("core_state") != "running",
                            "managed Daemon reopened Core without stopped intent")
                    if (current.get("core_desired_state") == "stopped" and
                            current.get("core_state") == "stopped" and
                            current.get("core_pid") in (None, 0) and
                            current.get("recovery_required") is False and
                            current.get("core_circuit_open") in (None, False) and
                            current.get("active_operation") in (None, "")):
                        break
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
    phase = "bootstrap"
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
                    node_thread = threading.Thread(target=node.serve_forever, daemon=True)
                    node_thread.start()
                    try:
                        document = local_document(node.server_address[1])
                        assert_synthetic_document(document, node.server_address[1])
                        expected_sha = None
                        staged_sha = None
                        staged_config_sha = None
                        promoted_generation = None

                        def first(daemon, sock, initial):
                            nonlocal expected_sha, staged_sha, staged_config_sha
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
                            probe_isolated_routes(echo.server_address[1],
                                                  b"managed-first-", node)
                            probe_isolated_failure(echo.server_address[1],
                                                   b"failed-first-", node)
                            require(committed_snapshot(
                                wait_status(args.app, env, "running"),
                                generation, "running", True) == pid,
                                "node failure unexpectedly restarted managed Core")
                            probe_isolated_routes(echo.server_address[1],
                                                  b"restored-first-", node)
                            staged_sha, staged_config_sha = stage_and_reject_stale_apply(
                                sock, generation, pid,
                                document, node.server_address[1], expected_sha,
                                compiled["config_sha256"], echo.server_address[1], node)
                            boot.checked([args.app, "core", "stop"], env, timeout=20)
                            stopped = wait_status(args.app, env, "stopped")
                            committed_snapshot(stopped, generation, "stopped", False, 2)
                            verify_stopped_ports()
                            return generation

                        phase = "initial-apply"
                        generation = run_daemon(args.app, args.core, root, env, first)
                        verify_stopped_ports()
                        require(node.calls >= 1 and not node.failed,
                                "synthetic selected node failed")

                        def restart(daemon, sock, initial):
                            nonlocal promoted_generation
                            committed_snapshot(initial, generation, "stopped", False, 2)
                            require(unix_json(
                                sock, "GET", "/v1/declaration/current").get("sha256")
                                == staged_sha,
                                "unapplied declaration did not survive Daemon restart")
                            cold.configured_caps(unix_json(
                                sock, "GET", "/v1/capabilities"))
                            boot.checked([args.app, "core", "start"], env, timeout=22)
                            running = wait_status(args.app, env, "running")
                            pid = committed_snapshot(running, generation, "running", True, 2)
                            verify_child(pid, daemon.pid, args.core)
                            assert_unapplied_core_unchanged(
                                unix_json(sock, "GET", "/v1/status"), generation, pid, 2)
                            probe_isolated_routes(echo.server_address[1],
                                                  b"managed-restart-", node)
                            probe_isolated_failure(echo.server_address[1],
                                                   b"failed-restart-", node)
                            require(committed_snapshot(
                                wait_status(args.app, env, "running"),
                                generation, "running", True, 2) == pid,
                                "node failure restarted the persisted Core")
                            probe_isolated_routes(echo.server_address[1],
                                                  b"restored-restart-", node)
                            promoted_generation, promoted_pid = promote_staged_generation(
                                sock, args.app, env, daemon.pid, args.core,
                                generation, pid, staged_sha, staged_config_sha,
                                echo.server_address[1], node)
                            probe_isolated_failure(echo.server_address[1],
                                                   b"failed-promoted-", node)
                            require(assert_promoted_core(
                                unix_json(sock, "GET", "/v1/status"),
                                generation, promoted_generation, pid, True)
                                == promoted_pid,
                                "promoted Core restarted after local node refusal")
                            probe_isolated_routes(echo.server_address[1],
                                                  b"restored-promoted-", node)
                            boot.checked([args.app, "core", "stop"], env, timeout=20)
                            stopped = wait_status(args.app, env, "stopped")
                            assert_promoted_core(stopped, generation,
                                                 promoted_generation, pid, False)
                            verify_stopped_ports()

                        phase = "staged-promotion"
                        run_daemon(args.app, args.core, root, env, restart)
                        require(type(promoted_generation) is int and
                                promoted_generation > generation,
                                "successfully applied generation was not persisted")

                        def promoted_restart(daemon, sock, initial):
                            nonlocal phase
                            phase = "crash-initial-check"
                            assert_promoted_core(initial, generation,
                                                 promoted_generation, None, False)
                            require(unix_json(
                                sock, "GET", "/v1/declaration/current").get("sha256")
                                == staged_sha,
                                "new applied generation lost its declaration on restart")
                            cold.configured_caps(unix_json(
                                sock, "GET", "/v1/capabilities"))
                            phase = "crash-core-start"
                            boot.checked([args.app, "core", "start"], env, timeout=22)
                            running = wait_status(args.app, env, "running")
                            new_pid = assert_promoted_core(
                                running, generation, promoted_generation, None, True)
                            verify_child(new_pid, daemon.pid, args.core)
                            phase = "crash-initial-routes"
                            probe_isolated_routes(echo.server_address[1],
                                                  b"promoted-restart-", node)
                            phase = "crash-initial-selected-refusal"
                            probe_isolated_failure(echo.server_address[1],
                                                   b"failed-promoted-restart-", node)
                            require(assert_promoted_core(
                                unix_json(sock, "GET", "/v1/status"),
                                generation, promoted_generation, None, True)
                                == new_pid,
                                "persisted promoted Core restarted unexpectedly")
                            phase = "crash-initial-selected-restored"
                            probe_isolated_routes(echo.server_address[1],
                                                  b"restored-promoted-restart-", node)
                            def crash_stage(label):
                                nonlocal phase
                                phase = label  # Only fixed internal test labels.
                            phase = "crash-held-entry"
                            probe_held_crash_recovery(
                                sock, daemon.pid, args.core,
                                generation, promoted_generation, new_pid,
                                echo.server_address[1], node,
                                stage_hook=crash_stage)
                            phase = "crash-explicit-stop"
                            boot.checked([args.app, "core", "stop"], env, timeout=20)
                            stopped = wait_status(args.app, env, "stopped")
                            assert_promoted_core(
                                stopped, generation, promoted_generation, None, False)
                            verify_stopped_ports()
                            # A stopped desired state must win over any pending
                            # retry after the one deliberately injected crash.
                            phase = "crash-stopped-intent-check"
                            time.sleep(2.2)
                            assert_promoted_core(
                                unix_json(sock, "GET", "/v1/status"),
                                generation, promoted_generation, None, False)
                            verify_stopped_ports()

                        phase = "crash-recovery"
                        run_daemon(args.app, args.core, root, env, promoted_restart)

                        def after_crash_stop(daemon, sock, initial):
                            assert_promoted_core(
                                initial, generation, promoted_generation, None, False)
                            require(unix_json(
                                sock, "GET", "/v1/declaration/current").get("sha256")
                                == staged_sha,
                                "post-crash stop lost promoted declaration digest")
                            verify_stopped_ports()
                            return True

                        phase = "post-crash-stop"
                        require(run_daemon(args.app, args.core, root, env,
                                           after_crash_stop) is True,
                                "post-crash stopped Daemon restart failed")
                        require(node.calls == 12 and node.rejections >= 5 and
                                not node.reject_connections and not node.failed,
                                "crash/restart recovery crossed or bypassed routes")

                        def bounded_lifecycle(daemon, sock, initial):
                            nonlocal phase
                            phase = "held-lifecycle-entry"
                            assert_promoted_core(initial, generation,
                                                 promoted_generation, None, False)
                            require(unix_json(
                                sock, "GET", "/v1/declaration/current").get("sha256")
                                == staged_sha,
                                "short lifecycle changed the declaration head")
                            def diagnostic_stage(label):
                                nonlocal phase
                                # Only fixed, test-generated stage labels are
                                # reported; never exception text or daemon logs.
                                phase = label
                            return probe_bounded_lifecycle_cycles(
                                args.app, env, sock, daemon.pid, args.core,
                                generation, promoted_generation,
                                echo.server_address[1], node,
                                stage_hook=diagnostic_stage)

                        phase = "held-session-lifecycle"
                        counts = run_daemon(args.app, args.core, root, env,
                                            bounded_lifecycle)
                        require(len(counts) == 3, "missing lifecycle FD samples")
                        # The sixth Daemon must start stopped after the
                        # three held client tunnels were explicitly severed.
                        # Only a fresh operator request may restart Core.
                        def after_cycles(daemon, sock, initial):
                            assert_promoted_core(initial, generation,
                                                 promoted_generation, None, False)
                            cold.configured_caps(unix_json(
                                sock, "GET", "/v1/capabilities"))
                            return probe_restart_after_held_stop(
                                args.app, env, sock, daemon.pid, args.core,
                                generation, promoted_generation,
                                echo.server_address[1], node, staged_sha)

                        phase = "held-stop-explicit-restart"
                        require(type(run_daemon(
                            args.app, args.core, root, env, after_cycles)) is int,
                            "post-held-stop explicit restart was not verified")

                        # After a second explicit stop, another cold Daemon
                        # open must not resurrect Core or the old TCP streams.
                        def final_stopped(daemon, sock, initial):
                            nonlocal phase
                            phase = "final-stopped-status"
                            assert_promoted_core(initial, generation,
                                                 promoted_generation, None, False)
                            require(unix_json(
                                sock, "GET", "/v1/declaration/current").get("sha256")
                                == staged_sha,
                                "final stopped restart lost declaration head")
                            phase = "final-stopped-listeners"
                            verify_stopped_ports()

                        phase = "final-stopped-open"
                        run_daemon(args.app, args.core, root, env, final_stopped)
                        phase = "final-node-accounting"
                        require(node.calls == 51 and node.rejections >= 11 and
                                not node.reject_connections and not node.failed,
                                "held-session restart or Selected routing drifted")
                        phase = "final-core-hash"
                        cold.hash_pinned_core(core, args.core_sha256)
                    finally:
                        node.shutdown()
                        node_thread.join(timeout=5)
                        echo.shutdown()
                        echo_thread.join(timeout=5)
        print("T24_AIRGAP_DAEMON_COMMITTED_CORE_LOOPBACK=ok")
        print("T24_AIRGAP_SELECTED_NODE_FAILURE_ISOLATED=ok")
        print("T24_AIRGAP_STAGED_REVISION_CAS_ISOLATED=ok")
        print("T24_AIRGAP_LIVE_GENERATION_HANDOFF=ok")
        print("T24_AIRGAP_PROMOTED_CRASH_RECOVERY=ok")
        print("T25_AIRGAP_SHORT_LIFECYCLE_SMOKE=ok")
        print("T25_AIRGAP_PARALLEL_LOOPBACK=ok")
        print("T25_AIRGAP_PARALLEL_REFUSAL_ISOLATED=ok")
        print("T25_AIRGAP_HELD_SESSIONS_STOPPED=ok")
        print("T25_AIRGAP_HELD_STOP_RESTART=ok")
        print("T25_AIRGAP_CRASH_HELD_SESSIONS_CLOSED=ok")
        print("T20_AIRGAP_BOUNDED_RECONNECT_FD=ok")
        print("T20_1000_RECONNECTS_VERIFIED=false")
        print("T25_72H_7D_30D_SOAK_VERIFIED=false")
        print("T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false")
        print("T24_OFFLINE_DISTRIBUTION_OR_RESTORE_APPROVED=false")
        return 0
    except (OSError, RuntimeError, ValueError, KeyError,
            subprocess.SubprocessError, http.client.HTTPException) as exc:
        # Emit only fixed, non-secret phase and exception class: daemon logs,
        # arbitrary exception strings, and runtime config must stay private.
        print("T24_AIRGAP_FAILURE_PHASE=" + phase, file=sys.stderr)
        print("T24_AIRGAP_FAILURE_CLASS=" + type(exc).__name__, file=sys.stderr)
        print("T24_AIRGAP_FAILURE_CODE=" +
              safe_airgap_failure_code(exc), file=sys.stderr)
        print("T24_AIRGAP_DAEMON_COMMITTED_CORE_LOOPBACK=refused",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
