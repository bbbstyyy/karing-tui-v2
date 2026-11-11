#!/usr/bin/env python3
"""ADR 0176: real Direct destination DNS, distinct from Outbound/Node DNS.

Sixth independent non-root native Linux network-none container: actual
approved managed Core and two disjoint, ephemeral UDP DNS responders.
All domain names are reserved .invalid names; every server maps ONLY its
own test name to 127.0.0.1. No TUN, public DNS or privileged listeners.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading

import t24_airgap_bootstrap as boot
import t24_airgap_managed_applied as applied
import t24_airgap_managed_cold_guard as cold
import t24_airgap_managed_dns as node_dns
import t24_airgap_loopback_core as loopback

DIRECT_DOMAIN = node_dns.DIRECT_DOMAIN
NODE_DOMAIN = node_dns.NODE_DOMAIN


def require(condition, message):
    boot.require(condition, message)


def direct_dns_document(socks_port, node_dns_port, direct_dns_port):
    """Exact V1 declaration with separate node and direct resolver roles."""
    for port in (socks_port, node_dns_port, direct_dns_port):
        require(type(port) is int and 1023 < port < 65536,
                "invalid Direct DNS fixture port")
    require(node_dns_port != direct_dns_port,
            "Direct DNS and node DNS listener ports must differ")
    doc = applied.local_document(socks_port)
    doc["dns"]["profiles"][0]["port"] = node_dns_port
    doc["dns"]["profiles"].append({
        "id": "direct-destination", "role": "direct", "transport": "udp",
        "server": "127.0.0.1", "port": direct_dns_port,
    })
    doc["dns"]["direct_profile_id"] = "direct-destination"
    assert_direct_dns_document(doc, socks_port, node_dns_port,
                               direct_dns_port)
    return doc


def assert_direct_dns_document(doc, socks_port, node_dns_port, direct_dns_port):
    """Never allow this DNS probe to add routes, remote servers or fallback."""
    for port in (socks_port, node_dns_port, direct_dns_port):
        require(type(port) is int and 1023 < port < 65536,
                "invalid Direct DNS fixture port")
    require(node_dns_port != direct_dns_port,
            "Direct DNS and node DNS listener ports must differ")
    expected = applied.local_document(socks_port)
    expected["dns"]["profiles"][0]["port"] = node_dns_port
    expected["dns"]["profiles"].append({
        "id": "direct-destination", "role": "direct", "transport": "udp",
        "server": "127.0.0.1", "port": direct_dns_port,
    })
    expected["dns"]["direct_profile_id"] = "direct-destination"
    require(type(doc) is dict and doc == expected,
            "unapproved Direct DNS declaration")


def probe_direct_domain_socks(port, echo_port, payload):
    """Real SOCKS5 ATYP=3 to direct; client never calls system DNS."""
    require(type(port) is int and port in (2080, 2081) and
            type(echo_port) is int and 0 < echo_port < 65536 and
            type(payload) is bytes and 1 <= len(payload) <= 128,
            "invalid Direct DNS SOCKS fixture")
    request = (b"\x05\x01\x00\x03" + bytes([len(DIRECT_DOMAIN)]) +
               DIRECT_DOMAIN + struct.pack("!H", echo_port))
    with socket.create_connection(("127.0.0.1", port), timeout=4) as conn:
        conn.settimeout(4)
        conn.sendall(b"\x05\x01\x00")
        require(applied.exact_read(conn, 2) == b"\x05\x00",
                "Direct DNS SOCKS greeting failed")
        conn.sendall(request)
        header = applied.exact_read(conn, 4)
        require(header[:3] == b"\x05\x00\x00",
                "Direct DNS SOCKS CONNECT failed")
        if header[3] == 1:
            applied.exact_read(conn, 4)
        elif header[3] == 4:
            applied.exact_read(conn, 16)
        elif header[3] == 3:
            length = applied.exact_read(conn, 1)[0]
            require(0 < length <= 255,
                    "Direct DNS SOCKS reply address invalid")
            applied.exact_read(conn, length)
        else:
            raise RuntimeError("Direct DNS SOCKS reply address invalid")
        applied.exact_read(conn, 2)
        conn.sendall(payload)
        require(applied.exact_read(
            conn, len(loopback.REPLY_PREFIX) + len(payload)) ==
            loopback.REPLY_PREFIX + payload,
            "Direct DNS SOCKS destination echo incorrect")


def audit_managed_direct_dns(sock, generation, expected_pid, echo_port,
                             node, outbound_dns, direct_dns):
    """Rule/Direct domain traffic must use direct-role UDP DNS, not node DNS."""
    require(type(generation) is int and generation > 0 and
            type(expected_pid) is int and expected_pid > 1 and
            type(echo_port) is int and 0 < echo_port < 65536 and
            type(node.calls) is int and node.calls == 0 and
            type(node.rejections) is int and node.rejections == 0 and
            not node.failed and not node.reject_connections and
            getattr(outbound_dns, "allowed_name", None) == NODE_DOMAIN and
            getattr(direct_dns, "allowed_name", None) == DIRECT_DOMAIN and
            outbound_dns.server_address[0] == "127.0.0.1" and
            direct_dns.server_address[0] == "127.0.0.1" and
            outbound_dns.server_address[1] != direct_dns.server_address[1],
            "invalid Direct DNS route preflight")
    before = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        before, generation, "running", True) == expected_pid and
        before.get("last_known_good_generation_id") == generation,
        "Direct DNS began on changed Core or LKG")
    with outbound_dns.counter_lock, direct_dns.counter_lock:
        require(not outbound_dns.receipts and not direct_dns.receipts and
                not outbound_dns.failed and not direct_dns.failed,
                "Direct DNS started with stale resolver receipts")
    for port in (2080, 2081):
        probe_direct_domain_socks(
            port, echo_port,
            b"direct-dns-real-" + str(port).encode("ascii"))
        require(node.calls == 0 and node.rejections == 0 and
                not node.failed and not outbound_dns.failed and
                not direct_dns.failed,
                "Direct DNS leaked Rule or Direct into Selected")
    # The second query may be cached by the Core; an actual A query from
    # either client is mandatory, independently observed by Direct DNS.
    count = node_dns.assert_dns_receipts(
        direct_dns, expected_name=DIRECT_DOMAIN)
    with outbound_dns.counter_lock:
        require(not outbound_dns.receipts and not outbound_dns.failed,
                "Direct destination DNS used Outbound/Node DNS")
    with direct_dns.counter_lock:
        direct_receipts = list(direct_dns.receipts)
    applied.probe_port(2082, echo_port, b"direct-dns-selected-numeric")
    with direct_dns.counter_lock:
        require(direct_dns.receipts == direct_receipts and
                not direct_dns.failed,
                "Selected numeric traffic queried Direct destination DNS")
    with outbound_dns.counter_lock:
        require(not outbound_dns.receipts and not outbound_dns.failed,
                "Selected numeric traffic queried Outbound/Node DNS")
    require(node.calls == 1 and node.rejections == 0 and
            not node.failed and not node.reject_connections and
            not node.hostname_requests and
            not node.rejected_hostname_requests,
            "Direct DNS Selected control did not use exact upstream")
    after = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        after, generation, "running", True) == expected_pid and
        after.get("last_known_good_generation_id") == generation and
        after.get("active_operation") in (None, ""),
        "Direct DNS replaced running Core or LKG")
    return count


def run_native_direct_dns(args):
    boot.ensure_airgap(args.arch)
    require(Path(args.app).is_absolute() and os.access(args.app, os.X_OK) and
            Path(args.core).is_absolute(), "native Direct DNS artifacts missing")
    cold.hash_pinned_core(Path(args.core), args.core_sha256)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(
            prefix="t24-direct-dns-", dir="/work") as tmp:
        root = Path(tmp)
        env = cold.fresh_env(root, args.core)
        with (loopback.LoopbackServer(
                ("127.0.0.1", 0), loopback.LoopbackResponder) as echo,
              applied.LocalSocksServer(
                  ("127.0.0.1", 0), applied.LocalSocksNode) as node,
              node_dns.NodeDNSServer(
                  ("127.0.0.1", 0), NODE_DOMAIN) as outbound_dns,
              node_dns.NodeDNSServer(
                  ("127.0.0.1", 0), DIRECT_DOMAIN) as direct_dns):
            echo_port = echo.server_address[1]
            node.echo_port = echo_port
            servers = (echo, node, outbound_dns, direct_dns)
            threads = [
                threading.Thread(target=srv.serve_forever, daemon=True)
                for srv in servers
            ]
            for thread in threads:
                thread.start()
            try:
                document = direct_dns_document(
                    node.server_address[1],
                    outbound_dns.server_address[1],
                    direct_dns.server_address[1])
                def work(daemon, sock, initial):
                    cold.configured_status(initial)
                    cold.configured_caps(applied.unix_json(
                        sock, "GET", "/v1/capabilities"))
                    created = applied.unix_json(
                        sock, "POST", "/v1/declaration",
                        {"expected_revision": 0,
                         "source": "lab:t24-direct-dns",
                         "document": document}, expected=201)
                    require(created.get("revision") == 1 and
                            type(created.get("sha256")) is str and
                            len(created["sha256"]) == 64,
                            "Direct DNS declaration commit failed")
                    compiled = applied.unix_json(
                        sock, "POST", "/v1/declaration/compile",
                        {"revision": 1})
                    require(compiled.get("declaration_sha256") ==
                            created["sha256"] and
                            compiled.get("rule_set_count") == 0 and
                            type(compiled.get("config_sha256")) is str and
                            len(compiled["config_sha256"]) == 64,
                            "Direct DNS native compiler receipt invalid")
                    committed = applied.unix_json(
                        sock, "POST", "/v1/declaration/apply",
                        {"declaration_revision": 1,
                         "expected_config_revision": 0}, timeout=85)
                    generation = committed.get("generation_id")
                    require(type(generation) is int and generation > 0 and
                            committed.get("target_config_revision") == 1 and
                            committed.get("config_sha256") ==
                            compiled["config_sha256"] and
                            committed.get("declaration_sha256") ==
                            created["sha256"],
                            "Direct DNS generation not committed")
                    applied.committed_snapshot(
                        applied.wait_status(args.app, env, "stopped"),
                        generation, "stopped", False)
                    started = False
                    try:
                        boot.checked(
                            [args.app, "core", "start"], env, timeout=22)
                        started = True
                        running = applied.wait_status(
                            args.app, env, "running")
                        pid = applied.committed_snapshot(
                            running, generation, "running", True)
                        applied.verify_child(pid, daemon.pid, args.core)
                        return audit_managed_direct_dns(
                            sock, generation, pid, echo_port, node,
                            outbound_dns, direct_dns)
                    finally:
                        if started:
                            boot.checked(
                                [args.app, "core", "stop"], env, timeout=20)
                            applied.committed_snapshot(
                                applied.wait_status(args.app, env, "stopped"),
                                generation, "stopped", False)
                            applied.verify_stopped_ports()
                count = applied.run_daemon(
                    args.app, args.core, root, env, work)
                require(type(count) is int and count >= 1 and
                        not outbound_dns.receipts and not outbound_dns.failed and
                        not direct_dns.failed and node.calls == 1 and
                        node.rejections == 0 and not node.failed,
                        "native Direct destination DNS evidence missing")
                cold.hash_pinned_core(Path(args.core), args.core_sha256)
            finally:
                for server in reversed(servers):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=5)


SAFE_CODES = {
    "invalid Direct DNS fixture port": "direct-dns-port",
    "Direct DNS and node DNS listener ports must differ": "direct-dns-port-alias",
    "unapproved Direct DNS declaration": "direct-dns-document",
    "invalid Direct DNS SOCKS fixture": "direct-dns-socks-args",
    "Direct DNS SOCKS greeting failed": "direct-dns-socks-greeting",
    "Direct DNS SOCKS CONNECT failed": "direct-dns-socks-connect",
    "Direct DNS SOCKS reply address invalid": "direct-dns-socks-reply",
    "Direct DNS SOCKS destination echo incorrect": "direct-dns-socks-echo",
    "invalid Direct DNS route preflight": "direct-dns-preflight",
    "Direct DNS began on changed Core or LKG": "direct-dns-stale",
    "Direct DNS started with stale resolver receipts": "direct-dns-preexisting",
    "Direct DNS leaked Rule or Direct into Selected": "direct-dns-cross-route",
    "Direct destination DNS used Outbound/Node DNS": "direct-dns-role-bypass",
    "Selected numeric traffic queried Direct destination DNS": "direct-dns-selected-query",
    "Selected numeric traffic queried Outbound/Node DNS": "direct-dns-node-query",
    "Direct DNS Selected control did not use exact upstream": "direct-dns-selected",
    "Direct DNS replaced running Core or LKG": "direct-dns-core-drift",
    "native Direct DNS artifacts missing": "direct-dns-artifact",
    "Direct DNS declaration commit failed": "direct-dns-commit",
    "Direct DNS native compiler receipt invalid": "direct-dns-compile",
    "Direct DNS generation not committed": "direct-dns-apply",
    "native Direct destination DNS evidence missing": "direct-dns-incomplete",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=boot.MACHINES)
    parser.add_argument("--app", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        run_native_direct_dns(args)
    except (OSError, RuntimeError, ValueError, KeyError, struct.error,
            subprocess.SubprocessError) as exc:
        # Never output dynamic DNS packets, private config or daemon logs.
        print("T22_AIRGAP_DIRECT_DESTINATION_DNS_UDP=refused",
              file=sys.stderr)
        print("T22_AIRGAP_DIRECT_DNS_FAILURE_CLASS=" +
              type(exc).__name__, file=sys.stderr)
        print("T22_AIRGAP_DIRECT_DNS_FAILURE_CODE=" +
              SAFE_CODES.get(str(exc), "unclassified"), file=sys.stderr)
        return 1
    print("T22_AIRGAP_DIRECT_DESTINATION_DNS_UDP=ok")
    print("T22_HOSTNAME_AND_UDP_VERIFIED=false")
    print("T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false")
    print("T20_1000_RECONNECTS_VERIFIED=false")
    print("T25_72H_7D_30D_SOAK_VERIFIED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
