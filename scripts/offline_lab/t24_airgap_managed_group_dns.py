#!/usr/bin/env python3
"""ADR 0178: real Group DNS TCP Selected detour, separate from Proxy DNS.

Eighth independent Linux network-none native container using the SHA-pinned
managed Core; strict .invalid names and ephemeral 127.0.0.1 listeners only.
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
import t24_airgap_loopback_core as loopback
import t24_airgap_managed_applied as applied
import t24_airgap_managed_cold_guard as cold
import t24_airgap_managed_direct_dns as direct
import t24_airgap_managed_dns as dns
import t24_airgap_managed_proxy_dns as proxy

GROUP_DOMAIN = dns.GROUP_DOMAIN
PROXY_DOMAIN = dns.PROXY_DOMAIN
DIRECT_DOMAIN = dns.DIRECT_DOMAIN
GROUP_PROFILE_ID = "group-selected-tcp"
GROUP_ID = "group-only-domain"


def require(condition, message):
    boot.require(condition, message)


def assert_fixture_ports(*ports):
    require(len(ports) == 5 and
            all(type(port) is int and 1023 < port < 65536 for port in ports)
            and len(set(ports)) == 5,
            "invalid Group DNS fixture ports")


def group_dns_document(node_port, node_dns_port, direct_port,
                       proxy_port, group_port):
    assert_fixture_ports(node_port, node_dns_port, direct_port,
                         proxy_port, group_port)
    doc = proxy.proxy_dns_document(node_port, node_dns_port, direct_port,
                                   proxy_port)
    doc["dns"]["profiles"].append({
        "id": GROUP_PROFILE_ID, "role": "group", "transport": "tcp",
        "server": "127.0.0.1", "port": group_port,
        "detour_target": {"kind": "current_selected"},
    })
    doc["routing"]["custom"].append({
        "id": GROUP_ID, "order": 1, "enabled": True,
        "target": {"kind": "direct"},
        "dns_profile_id": GROUP_PROFILE_ID,
        "match": {"op": "atom", "predicate": {
            "kind": "domain", "value": GROUP_DOMAIN.decode("ascii"),
        }},
    })
    assert_group_document(doc, node_port, node_dns_port, direct_port,
                          proxy_port, group_port)
    return doc


def assert_group_document(doc, node_port, node_dns_port, direct_port,
                          proxy_port, group_port):
    assert_fixture_ports(node_port, node_dns_port, direct_port,
                         proxy_port, group_port)
    expected = proxy.proxy_dns_document(node_port, node_dns_port, direct_port,
                                        proxy_port)
    expected["dns"]["profiles"].append({
        "id": GROUP_PROFILE_ID, "role": "group", "transport": "tcp",
        "server": "127.0.0.1", "port": group_port,
        "detour_target": {"kind": "current_selected"},
    })
    expected["routing"]["custom"].append({
        "id": GROUP_ID, "order": 1, "enabled": True,
        "target": {"kind": "direct"},
        "dns_profile_id": GROUP_PROFILE_ID,
        "match": {"op": "atom", "predicate": {
            "kind": "domain", "value": GROUP_DOMAIN.decode("ascii"),
        }},
    })
    require(type(doc) is dict and doc == expected,
            "unapproved Group DNS declaration")


def probe_group_domain(echo_port, payload):
    """Rule:2080 SOCKS5 DOMAIN; the client itself never resolves the name."""
    require(type(echo_port) is int and 1023 < echo_port < 65536 and
            type(payload) is bytes and 1 <= len(payload) <= 128,
            "invalid Group DNS application fixture")
    request = (b"\x05\x01\x00\x03" + bytes([len(GROUP_DOMAIN)]) +
               GROUP_DOMAIN + struct.pack("!H", echo_port))
    with socket.create_connection(("127.0.0.1", 2080), timeout=4) as conn:
        conn.settimeout(4)
        conn.sendall(b"\x05\x01\x00")
        require(applied.exact_read(conn, 2) == b"\x05\x00",
                "Group DNS SOCKS greeting refused")
        conn.sendall(request)
        header = applied.exact_read(conn, 4)
        require(header[:3] == b"\x05\x00\x00",
                "Group DNS SOCKS CONNECT refused")
        if header[3] == 1:
            applied.exact_read(conn, 4)
        elif header[3] == 4:
            applied.exact_read(conn, 16)
        elif header[3] == 3:
            length = applied.exact_read(conn, 1)[0]
            require(0 < length <= 255,
                    "Group DNS SOCKS response address invalid")
            applied.exact_read(conn, length)
        else:
            raise RuntimeError("Group DNS SOCKS response address invalid")
        applied.exact_read(conn, 2)
        conn.sendall(payload)
        require(applied.exact_read(
            conn, len(loopback.REPLY_PREFIX) + len(payload)) ==
            loopback.REPLY_PREFIX + payload,
            "Group DNS SOCKS application echo mismatch")


def verify_upstream(node, echo_port, proxy_port, group_port,
                    expect_group, expect_proxy):
    """A DNS answer WITHOUT SOCKS CONNECT to its port never counts."""
    with node.counter_lock:
        destinations = list(node.destination_receipts)
        hostname_receipts = list(node.hostname_requests)
        denied = list(node.rejected_hostname_requests)
        accepted = node.calls
        rejections = node.rejections
        failed = node.failed
    allowed_ports = {echo_port, proxy_port, group_port}
    require(accepted == len(destinations) and accepted > 0 and
            accepted <= 2 * proxy.MAX_TCP_DNS_QUERIES + 1 and
            rejections == 0 and not denied and not failed and
            not node.reject_connections and
            all(addr == "127.0.0.1" and port in allowed_ports
                for _, addr, port in destinations) and
            all(name == PROXY_DOMAIN and port == echo_port
                for name, port in hostname_receipts),
            "Group DNS unexpected Selected upstream destinations")
    group_count = sum(port == group_port for _, _, port in destinations)
    proxy_count = sum(port == proxy_port for _, _, port in destinations)
    # Group's APPLICATION target is explicitly DIRECT; its own DNS transport
    # is separately detoured over Selected SOCKS. A Group app connection
    # through Selected is a failure, even if an identical echo came back.
    echo_count = sum(port == echo_port for _, _, port in destinations)
    proxy_app = sum(host == PROXY_DOMAIN and port == echo_port
                    for host, _, port in destinations)
    require(sorted(hostname_receipts) == sorted(
        (host, port) for host, _, port in destinations
        if host is not None and port == echo_port),
        "Group DNS raw SOCKS hostname receipts drifted")
    require((1 <= group_count <= proxy.MAX_TCP_DNS_QUERIES
             if expect_group else group_count == 0),
            "Group DNS TCP transport did not use Selected SOCKS")
    require((1 <= proxy_count <= proxy.MAX_TCP_DNS_QUERIES
             if expect_proxy else proxy_count == 0),
            "Proxy DNS TCP transport did not use Selected SOCKS")
    require(echo_count == int(expect_proxy),
            "Group DNS Direct application leaked into Selected SOCKS")
    require(proxy_app == int(expect_proxy),
            "Selected control did not use its Proxy DNS application")
    return accepted, group_count, proxy_count


def audit_managed_group_dns(sock, generation, expected_pid, echo_port,
                            node, node_dns, direct_dns, proxy_dns, group_dns):
    require(type(generation) is int and generation > 0 and
            type(expected_pid) is int and expected_pid > 1 and
            type(echo_port) is int and 1023 < echo_port < 65536 and
            node.calls == 0 and node.rejections == 0 and
            not node.failed and not node.reject_connections and
            getattr(node, "destination_receipts", None) == [] and
            node.echo_port == echo_port and
            node.http_port == proxy_dns.server_address[1] and
            node.group_dns_port == group_dns.server_address[1] and
            node_dns.allowed_name == dns.NODE_DOMAIN and
            direct_dns.allowed_name == DIRECT_DOMAIN and
            proxy_dns.allowed_name == PROXY_DOMAIN and
            group_dns.allowed_name == GROUP_DOMAIN,
            "Group DNS managed Core fixture invalid")
    ports = (node.server_address[1], node_dns.server_address[1],
             direct_dns.server_address[1], proxy_dns.server_address[1],
             group_dns.server_address[1])
    assert_fixture_ports(*ports)
    before = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        before, generation, "running", True) == expected_pid and
        before.get("last_known_good_generation_id") == generation,
        "Group DNS started on wrong Core or LKG")
    for server in (node_dns, direct_dns, proxy_dns, group_dns):
        with server.counter_lock:
            require(not server.receipts and not server.failed,
                    "Group DNS started with old DNS receipts")
    # Both Direct and Rule non-matching custom group controls use ONLY
    # Direct UDP DNS and never touch selected or either TCP resolver.
    for port in (2081, 2080):
        direct.probe_direct_domain_socks(
            port, echo_port, b"group-nonmatching-" + str(port).encode())
        require(node.calls == 0 and node.rejections == 0 and not node.failed,
                "Group DNS nonmatching control selected proxy")
    direct_count = dns.assert_dns_receipts(
        direct_dns, expected_name=DIRECT_DOMAIN)
    with direct_dns.counter_lock:
        direct_snapshot = list(direct_dns.receipts)
    with node_dns.counter_lock, proxy_dns.counter_lock, group_dns.counter_lock:
        require(not node_dns.receipts and not proxy_dns.receipts and
                not group_dns.receipts,
                "Group DNS control queried unrelated resolver")
    # Custom Rule group target DIRECT, but its DNS resolver detours via Selected.
    probe_group_domain(echo_port, b"group-explicit-selected-route")
    group_count = proxy.assert_proxy_dns_receipts(
        group_dns, expected_name=GROUP_DOMAIN)
    verify_upstream(node, echo_port, proxy_dns.server_address[1],
                    group_dns.server_address[1], True, False)
    with proxy_dns.counter_lock, group_dns.counter_lock:
        require(not proxy_dns.receipts and not proxy_dns.failed and
                not group_dns.failed,
                "Group DNS incorrectly used global Proxy resolver")
        group_snapshot = list(group_dns.receipts)
    with direct_dns.counter_lock, node_dns.counter_lock:
        require(direct_dns.receipts == direct_snapshot and
                not node_dns.receipts and not direct_dns.failed and
                not node_dns.failed,
                "Group DNS leaked to Direct or Node resolver")
    # Selected synthetic route has its *own* Proxy resolver: this must NOT
    # reuse the Group DNS profile or send the Selected domain to group DNS.
    applied.probe_selected_socks_domain(
        echo_port, b"group-proxy-control-tunnel")
    proxy_count = proxy.assert_proxy_dns_receipts(
        proxy_dns, expected_name=PROXY_DOMAIN)
    verify_upstream(node, echo_port, proxy_dns.server_address[1],
                    group_dns.server_address[1], True, True)
    with group_dns.counter_lock, direct_dns.counter_lock, node_dns.counter_lock:
        require(group_dns.receipts == group_snapshot and
                direct_dns.receipts == direct_snapshot and
                not node_dns.receipts and
                not group_dns.failed and not direct_dns.failed and
                not node_dns.failed,
                "Group DNS cache or resolver contaminated other role")
    after = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        after, generation, "running", True) == expected_pid and
        after.get("last_known_good_generation_id") == generation and
        after.get("active_operation") in (None, ""),
        "Group DNS changed running Core or LKG")
    return direct_count, group_count, proxy_count


def run_native_group_dns(args):
    boot.ensure_airgap(args.arch)
    require(Path(args.app).is_absolute() and os.access(args.app, os.X_OK) and
            Path(args.core).is_absolute(), "Group DNS artifacts missing")
    cold.hash_pinned_core(Path(args.core), args.core_sha256)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="t24-group-dns-",
                                     dir="/work") as tmp:
        root = Path(tmp)
        env = cold.fresh_env(root, args.core)
        with (loopback.LoopbackServer(
                ("127.0.0.1", 0), loopback.LoopbackResponder) as echo,
              applied.LocalSocksServer(
                  ("127.0.0.1", 0), applied.LocalSocksNode) as node,
              dns.NodeDNSServer(
                  ("127.0.0.1", 0), dns.NODE_DOMAIN) as node_dns,
              dns.NodeDNSServer(
                  ("127.0.0.1", 0), DIRECT_DOMAIN) as direct_dns,
              proxy.ProxyTCPDNSServer(
                  ("127.0.0.1", 0), PROXY_DOMAIN) as proxy_dns,
              proxy.ProxyTCPDNSServer(
                  ("127.0.0.1", 0), GROUP_DOMAIN) as group_dns):
            echo_port = echo.server_address[1]
            node.echo_port = echo_port
            node.http_port = proxy_dns.server_address[1]
            node.group_dns_port = group_dns.server_address[1]
            node.destination_receipts = []
            servers = (echo, node, node_dns, direct_dns,
                       proxy_dns, group_dns)
            threads = [threading.Thread(
                target=srv.serve_forever, daemon=True) for srv in servers]
            for thread in threads:
                thread.start()
            try:
                doc = group_dns_document(
                    node.server_address[1], node_dns.server_address[1],
                    direct_dns.server_address[1],
                    proxy_dns.server_address[1],
                    group_dns.server_address[1])

                def work(daemon, sock, initial):
                    cold.configured_status(initial)
                    cold.configured_caps(applied.unix_json(
                        sock, "GET", "/v1/capabilities"))
                    created = applied.unix_json(
                        sock, "POST", "/v1/declaration",
                        {"expected_revision": 0,
                         "source": "lab:t24-group-dns",
                         "document": doc}, expected=201)
                    require(created.get("revision") == 1 and
                            type(created.get("sha256")) is str and
                            len(created["sha256"]) == 64,
                            "Group DNS declaration commit failed")
                    compiled = applied.unix_json(
                        sock, "POST", "/v1/declaration/compile",
                        {"revision": 1})
                    require(compiled.get("declaration_sha256") ==
                            created["sha256"] and
                            compiled.get("rule_set_count") == 0 and
                            type(compiled.get("config_sha256")) is str and
                            len(compiled["config_sha256"]) == 64,
                            "Group DNS native compiler receipt invalid")
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
                            "Group DNS generation did not commit")
                    applied.committed_snapshot(
                        applied.wait_status(args.app, env, "stopped"),
                        generation, "stopped", False)
                    started = False
                    try:
                        boot.checked([args.app, "core", "start"],
                                     env, timeout=22)
                        started = True
                        running = applied.wait_status(
                            args.app, env, "running")
                        pid = applied.committed_snapshot(
                            running, generation, "running", True)
                        applied.verify_child(pid, daemon.pid, args.core)
                        return audit_managed_group_dns(
                            sock, generation, pid, echo_port, node,
                            node_dns, direct_dns, proxy_dns, group_dns)
                    finally:
                        if started:
                            boot.checked([args.app, "core", "stop"],
                                         env, timeout=20)
                            applied.committed_snapshot(
                                applied.wait_status(
                                    args.app, env, "stopped"),
                                generation, "stopped", False)
                            applied.verify_stopped_ports()
                counts = applied.run_daemon(
                    args.app, args.core, root, env, work)
                require(type(counts) is tuple and len(counts) == 3 and
                        all(type(x) is int and x >= 1 for x in counts) and
                        not node.failed and not node.rejections and
                        not node_dns.failed and not direct_dns.failed and
                        not group_dns.failed and not proxy_dns.failed and
                        not node_dns.receipts,
                        "Group DNS native evidence incomplete after stop")
                cold.hash_pinned_core(Path(args.core), args.core_sha256)
            finally:
                for server in reversed(servers):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=5)


SAFE_CODES = {
    "invalid Group DNS fixture ports": "group-dns-fixture-ports",
    "unapproved Group DNS declaration": "group-dns-declaration",
    "invalid Group DNS application fixture": "group-dns-client-args",
    "Group DNS SOCKS greeting refused": "group-dns-greeting",
    "Group DNS SOCKS CONNECT refused": "group-dns-connect",
    "Group DNS SOCKS response address invalid": "group-dns-reply",
    "Group DNS SOCKS application echo mismatch": "group-dns-echo",
    "Group DNS unexpected Selected upstream destinations": "group-dns-unapproved-upstream",
    "Group DNS raw SOCKS hostname receipts drifted": "group-dns-raw-host-drift",
    "Group DNS TCP transport did not use Selected SOCKS": "group-dns-tcp-detour",
    "Proxy DNS TCP transport did not use Selected SOCKS": "group-dns-proxy-detour",
    "Group DNS Direct application leaked into Selected SOCKS": "group-dns-app-leak",
    "Selected control did not use its Proxy DNS application": "group-dns-proxy-app-bypass",
    "Group DNS managed Core fixture invalid": "group-dns-preflight",
    "Group DNS started on wrong Core or LKG": "group-dns-stale-core",
    "Group DNS started with old DNS receipts": "group-dns-old-receipts",
    "Group DNS nonmatching control selected proxy": "group-dns-cross-route",
    "Group DNS control queried unrelated resolver": "group-dns-control-leak",
    "Group DNS incorrectly used global Proxy resolver": "group-dns-proxy-cross",
    "Group DNS leaked to Direct or Node resolver": "group-dns-direct-node-leak",
    "Group DNS cache or resolver contaminated other role": "group-dns-cache-leak",
    "Group DNS changed running Core or LKG": "group-dns-core-drift",
    "Group DNS artifacts missing": "group-dns-artifacts",
    "Group DNS declaration commit failed": "group-dns-commit",
    "Group DNS native compiler receipt invalid": "group-dns-compile",
    "Group DNS generation did not commit": "group-dns-apply",
    "Group DNS native evidence incomplete after stop": "group-dns-incomplete",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=boot.MACHINES)
    parser.add_argument("--app", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        run_native_group_dns(args)
    except (OSError, RuntimeError, ValueError, KeyError, struct.error,
            subprocess.SubprocessError) as exc:
        print("T22_AIRGAP_GROUP_DNS_TCP_SELECTED_DETOUR=refused",
              file=sys.stderr)
        print("T22_AIRGAP_GROUP_DNS_FAILURE_CLASS=" +
              type(exc).__name__, file=sys.stderr)
        print("T22_AIRGAP_GROUP_DNS_FAILURE_CODE=" +
              SAFE_CODES.get(str(exc), "unclassified"), file=sys.stderr)
        return 1
    print("T22_AIRGAP_GROUP_DNS_TCP_SELECTED_DETOUR=ok")
    print("T22_HOSTNAME_AND_UDP_VERIFIED=false")
    print("T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false")
    print("T20_1000_RECONNECTS_VERIFIED=false")
    print("T25_72H_7D_30D_SOAK_VERIFIED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
