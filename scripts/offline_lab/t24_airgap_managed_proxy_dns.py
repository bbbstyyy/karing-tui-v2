#!/usr/bin/env python3
"""ADR 0177: real Proxy destination DNS over selected SOCKS5 TCP detour.

Seventh independent Linux amd64/arm64 read-only network-none native container.
An approved managed Core must send test-only Proxy DNS TCP questions through
the synthetic Selected SOCKS upstream to a local strict DNS responder.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import socketserver
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

PROXY_DOMAIN = dns.PROXY_DOMAIN
DIRECT_DOMAIN = dns.DIRECT_DOMAIN
MAX_TCP_DNS_QUERIES = 12


def require(value, message):
    boot.require(value, message)


def proxy_dns_document(node_port, node_dns_port, direct_dns_port,
                       proxy_dns_port):
    """Only one local SOCKS node and three strictly pinned resolver roles."""
    assert_fixture_ports(node_port, node_dns_port, direct_dns_port,
                         proxy_dns_port)
    doc = direct.direct_dns_document(
        node_port, node_dns_port, direct_dns_port)
    doc["dns"]["profiles"].append({
        "id": "proxy-selected-tcp", "role": "proxy", "transport": "tcp",
        "server": "127.0.0.1", "port": proxy_dns_port,
    })
    doc["dns"]["proxy_profile_id"] = "proxy-selected-tcp"
    assert_proxy_dns_document(doc, node_port, node_dns_port,
                              direct_dns_port, proxy_dns_port)
    return doc


def assert_fixture_ports(node_port, node_dns_port, direct_dns_port,
                         proxy_dns_port):
    require(all(type(port) is int and 1023 < port < 65536 for port in
                (node_port, node_dns_port, direct_dns_port, proxy_dns_port)),
            "invalid Proxy DNS fixture port")
    require(node_dns_port != direct_dns_port and
            node_port != proxy_dns_port,
            "Proxy DNS fixture ports alias")


def assert_proxy_dns_document(doc, node_port, node_dns_port, direct_dns_port,
                              proxy_dns_port):
    assert_fixture_ports(node_port, node_dns_port, direct_dns_port,
                         proxy_dns_port)
    expected = direct.direct_dns_document(
        node_port, node_dns_port, direct_dns_port)
    expected["dns"]["profiles"].append({
        "id": "proxy-selected-tcp", "role": "proxy", "transport": "tcp",
        "server": "127.0.0.1", "port": proxy_dns_port,
    })
    expected["dns"]["proxy_profile_id"] = "proxy-selected-tcp"
    require(type(doc) is dict and doc == expected,
            "unapproved Proxy DNS declaration")


class ProxyTCPDNSResponder(socketserver.BaseRequestHandler):
    """TCP/53-style two-byte length framing on an ephemeral localhost port."""

    def handle(self):
        conn = self.request
        conn.settimeout(4)
        handled = 0
        try:
            while handled < MAX_TCP_DNS_QUERIES:
                prefix = conn.recv(2)
                if not prefix:
                    return
                if len(prefix) == 1:
                    prefix += applied.exact_read(conn, 1)
                size = struct.unpack("!H", prefix)[0]
                require(17 <= size <= dns.MAX_DNS_DATAGRAM,
                        "unapproved Proxy DNS TCP question length")
                packet = applied.exact_read(conn, size)
                reply, receipt = dns.answer_node_dns(
                    packet, self.server.allowed_name)
                with self.server.counter_lock:
                    require(len(self.server.receipts) < MAX_TCP_DNS_QUERIES,
                            "too many Proxy DNS TCP questions")
                    self.server.receipts.append(receipt)
                conn.sendall(struct.pack("!H", len(reply)) + reply)
                handled += 1
        except socket.timeout:
            # Idle close after a complete response is normal for TCP DNS.
            if not handled:
                self.server.failed = True
        except (OSError, ValueError, RuntimeError, struct.error):
            with self.server.counter_lock:
                self.server.failed = True


class ProxyTCPDNSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, allowed_name=PROXY_DOMAIN):
        require(type(allowed_name) is bytes and
                allowed_name in (PROXY_DOMAIN, dns.GROUP_DOMAIN),
                "unapproved TCP DNS fixture name")
        require(address[0] == "127.0.0.1" and
                type(address[1]) is int and address[1] == 0,
                "Proxy DNS must listen on ephemeral loopback")
        super().__init__(address, ProxyTCPDNSResponder)
        self.allowed_name = allowed_name
        self.counter_lock = threading.Lock()
        self.receipts = []
        self.failed = False


def assert_proxy_dns_receipts(server, expected_name=PROXY_DOMAIN):
    require(type(getattr(server, "receipts", None)) is list and
            getattr(server, "counter_lock", None) is not None and
            not getattr(server, "failed", True),
            "Proxy DNS TCP responder failed")
    with server.counter_lock:
        receipts = list(server.receipts)
    require(1 <= len(receipts) <= MAX_TCP_DNS_QUERIES and
            any(name.lower() == expected_name and kind == 1
                for name, kind in receipts) and
            all(type(name) is bytes and name.lower() == expected_name and
                type(kind) is int and kind in (1, 28, 65)
                for name, kind in receipts),
            "Proxy DNS TCP A query not independently observed")
    return len(receipts)


def audit_managed_proxy_dns(sock, generation, expected_pid, echo_port,
                            node, outbound_dns, direct_dns, proxy_dns):
    """Demand real TCP DNS query through Selected + selected app echo."""
    require(type(generation) is int and generation > 0 and
            type(expected_pid) is int and expected_pid > 1 and
            type(echo_port) is int and 0 < echo_port < 65536 and
            type(node.calls) is int and node.calls == 0 and
            type(node.rejections) is int and node.rejections == 0 and
            not node.failed and not node.reject_connections and
            getattr(node, "destination_receipts", None) == [] and
            node.http_port == proxy_dns.server_address[1] and
            node.echo_port == echo_port and
            getattr(outbound_dns, "allowed_name", None) == dns.NODE_DOMAIN and
            getattr(direct_dns, "allowed_name", None) == DIRECT_DOMAIN and
            proxy_dns.server_address[0] == "127.0.0.1" and
            outbound_dns.server_address[1] != direct_dns.server_address[1],
            "invalid Proxy DNS managed Core fixture")
    before = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        before, generation, "running", True) == expected_pid and
        before.get("last_known_good_generation_id") == generation,
        "Proxy DNS began on changed Core")
    with (outbound_dns.counter_lock, direct_dns.counter_lock,
          proxy_dns.counter_lock, node.counter_lock):
        require(not outbound_dns.receipts and not direct_dns.receipts and
                not proxy_dns.receipts and not node.destination_receipts and
                not outbound_dns.failed and not direct_dns.failed and
                not proxy_dns.failed,
                "Proxy DNS began with preexisting requests")
    # Direct DNS isolation control. Both must complete an actual domain
    # target roundtrip and may share an in-Core DNS cache.
    for port in (2080, 2081):
        direct.probe_direct_domain_socks(
            port, echo_port,
            b"proxy-dns-direct-control-" + str(port).encode("ascii"))
        require(node.calls == 0 and node.rejections == 0 and
                not node.failed and not outbound_dns.failed and
                not direct_dns.failed and not proxy_dns.failed,
                "Direct DNS control crossed Selected proxy")
    direct_count = dns.assert_dns_receipts(
        direct_dns, expected_name=DIRECT_DOMAIN)
    with direct_dns.counter_lock:
        direct_snapshot = list(direct_dns.receipts)
    with outbound_dns.counter_lock, proxy_dns.counter_lock:
        require(not outbound_dns.receipts and not proxy_dns.receipts,
                "Direct DNS control consulted the wrong resolver")
    # Real SOCKS5 DOMAIN from numeric-local Selected: the compiler emits a
    # Proxy DNS resolve action with detour to CurrentSelected, so a valid
    # DNS response must traverse the synthetic SOCKS upstream as TCP.
    applied.probe_selected_socks_domain(
        echo_port, b"proxy-dns-selected-tunnel")
    proxy_count = assert_proxy_dns_receipts(proxy_dns)
    with node.counter_lock:
        destinations = list(node.destination_receipts)
        domain_receipts = list(node.hostname_requests)
        rejected = list(node.rejected_hostname_requests)
        calls, denials = node.calls, node.rejections
    require(2 <= calls <= MAX_TCP_DNS_QUERIES + 1 and
            calls == len(destinations) and denials == 0 and
            not rejected and not node.failed and
            not node.reject_connections and
            sum(target_port == echo_port for _, _, target_port
                in destinations) == 1 and
            1 <= sum(target_port == proxy_dns.server_address[1]
                     for _, _, target_port in destinations)
            <= MAX_TCP_DNS_QUERIES and
            all(addr == "127.0.0.1" and port in
                (echo_port, proxy_dns.server_address[1])
                for _, addr, port in destinations) and
            all(domain == PROXY_DOMAIN and port == echo_port
                for domain, port in domain_receipts),
            "Proxy DNS did not traverse exact Selected SOCKS upstream")
    with direct_dns.counter_lock, outbound_dns.counter_lock:
        require(direct_dns.receipts == direct_snapshot and
                not outbound_dns.receipts and
                not direct_dns.failed and not outbound_dns.failed,
                "Proxy DNS leaked into Direct or Outbound resolver")
    after = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        after, generation, "running", True) == expected_pid and
        after.get("last_known_good_generation_id") == generation and
        after.get("active_operation") in (None, ""),
        "Proxy DNS replaced approved Core or LKG")
    return direct_count, proxy_count


def run_native_proxy_dns(args):
    boot.ensure_airgap(args.arch)
    require(Path(args.app).is_absolute() and os.access(args.app, os.X_OK) and
            Path(args.core).is_absolute(), "Proxy DNS artifacts missing")
    cold.hash_pinned_core(Path(args.core), args.core_sha256)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(
            prefix="t24-proxy-dns-", dir="/work") as tmp:
        root = Path(tmp)
        env = cold.fresh_env(root, args.core)
        with (loopback.LoopbackServer(
                ("127.0.0.1", 0), loopback.LoopbackResponder) as echo,
              applied.LocalSocksServer(
                  ("127.0.0.1", 0), applied.LocalSocksNode) as node,
              dns.NodeDNSServer(
                  ("127.0.0.1", 0), dns.NODE_DOMAIN) as outbound_dns,
              dns.NodeDNSServer(
                  ("127.0.0.1", 0), DIRECT_DOMAIN) as direct_dns,
              ProxyTCPDNSServer(("127.0.0.1", 0)) as proxy_dns):
            echo_port = echo.server_address[1]
            node.echo_port = echo_port
            node.http_port = proxy_dns.server_address[1]
            node.destination_receipts = []
            servers = (echo, node, outbound_dns, direct_dns, proxy_dns)
            threads = [
                threading.Thread(target=server.serve_forever, daemon=True)
                for server in servers
            ]
            for thread in threads:
                thread.start()
            try:
                doc = proxy_dns_document(
                    node.server_address[1],
                    outbound_dns.server_address[1],
                    direct_dns.server_address[1],
                    proxy_dns.server_address[1])

                def work(daemon, sock, initial):
                    cold.configured_status(initial)
                    cold.configured_caps(applied.unix_json(
                        sock, "GET", "/v1/capabilities"))
                    created = applied.unix_json(
                        sock, "POST", "/v1/declaration",
                        {"expected_revision": 0,
                         "source": "lab:t24-proxy-dns",
                         "document": doc}, expected=201)
                    require(created.get("revision") == 1 and
                            type(created.get("sha256")) is str and
                            len(created["sha256"]) == 64,
                            "Proxy DNS declaration commit failed")
                    compiled = applied.unix_json(
                        sock, "POST", "/v1/declaration/compile",
                        {"revision": 1})
                    require(compiled.get("declaration_sha256") ==
                            created["sha256"] and
                            compiled.get("rule_set_count") == 0 and
                            type(compiled.get("config_sha256")) is str and
                            len(compiled["config_sha256"]) == 64,
                            "Proxy DNS native compilation failed")
                    applied_receipt = applied.unix_json(
                        sock, "POST", "/v1/declaration/apply",
                        {"declaration_revision": 1,
                         "expected_config_revision": 0}, timeout=85)
                    generation = applied_receipt.get("generation_id")
                    require(type(generation) is int and generation > 0 and
                            applied_receipt.get("target_config_revision") == 1
                            and applied_receipt.get("config_sha256") ==
                            compiled["config_sha256"] and
                            applied_receipt.get("declaration_sha256") ==
                            created["sha256"],
                            "Proxy DNS native apply was not committed")
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
                        return audit_managed_proxy_dns(
                            sock, generation, pid, echo_port, node,
                            outbound_dns, direct_dns, proxy_dns)
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
                require(type(counts) is tuple and len(counts) == 2 and
                        all(type(v) is int and v >= 1 for v in counts) and
                        not outbound_dns.failed and not direct_dns.failed and
                        not proxy_dns.failed and not node.failed and
                        not outbound_dns.receipts and node.rejections == 0,
                        "Proxy DNS experiment incomplete after Core stop")
                cold.hash_pinned_core(Path(args.core), args.core_sha256)
            finally:
                for server in reversed(servers):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=5)


SAFE_CODES = {
    "invalid Proxy DNS fixture port": "proxy-dns-fixture-port",
    "unapproved TCP DNS fixture name": "proxy-dns-fixture-name",
    "Proxy DNS fixture ports alias": "proxy-dns-port-alias",
    "unapproved Proxy DNS declaration": "proxy-dns-document",
    "Proxy DNS must listen on ephemeral loopback": "proxy-dns-listener",
    "unapproved Proxy DNS TCP question length": "proxy-dns-length",
    "too many Proxy DNS TCP questions": "proxy-dns-excess",
    "Proxy DNS TCP responder failed": "proxy-dns-responder",
    "Proxy DNS TCP A query not independently observed": "proxy-dns-no-A",
    "invalid Proxy DNS managed Core fixture": "proxy-dns-preflight",
    "Proxy DNS began on changed Core": "proxy-dns-stale-core",
    "Proxy DNS began with preexisting requests": "proxy-dns-old-receipts",
    "Direct DNS control crossed Selected proxy": "proxy-dns-cross-route",
    "Direct DNS control consulted the wrong resolver": "proxy-dns-direct-leak",
    "Proxy DNS did not traverse exact Selected SOCKS upstream": "proxy-dns-bypass",
    "Proxy DNS leaked into Direct or Outbound resolver": "proxy-dns-resolver-leak",
    "Proxy DNS replaced approved Core or LKG": "proxy-dns-core-drift",
    "Proxy DNS artifacts missing": "proxy-dns-artifacts",
    "Proxy DNS declaration commit failed": "proxy-dns-commit",
    "Proxy DNS native compilation failed": "proxy-dns-compile",
    "Proxy DNS native apply was not committed": "proxy-dns-apply",
    "Proxy DNS experiment incomplete after Core stop": "proxy-dns-incomplete",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=boot.MACHINES)
    parser.add_argument("--app", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        run_native_proxy_dns(args)
    except (OSError, RuntimeError, ValueError, KeyError, struct.error,
            subprocess.SubprocessError) as exc:
        print("T22_AIRGAP_PROXY_DNS_TCP_SELECTED_DETOUR=refused",
              file=sys.stderr)
        print("T22_AIRGAP_PROXY_DNS_FAILURE_CLASS=" +
              type(exc).__name__, file=sys.stderr)
        print("T22_AIRGAP_PROXY_DNS_FAILURE_CODE=" +
              SAFE_CODES.get(str(exc), "unclassified"), file=sys.stderr)
        return 1
    print("T22_AIRGAP_PROXY_DNS_TCP_SELECTED_DETOUR=ok")
    print("T22_HOSTNAME_AND_UDP_VERIFIED=false")
    print("T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false")
    print("T20_1000_RECONNECTS_VERIFIED=false")
    print("T25_72H_7D_30D_SOAK_VERIFIED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
