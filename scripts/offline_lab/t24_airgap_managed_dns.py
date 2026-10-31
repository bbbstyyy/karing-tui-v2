#!/usr/bin/env python3
"""ADR 0175: real approved Core Outbound/Node DNS against loopback UDP only.

Separate fifth Linux network-none, nonroot, read-only native container. An
ephemeral UDP responder resolves one reserved node-server name to 127.0.0.1.
No public DNS, TUN, privileged 53 listener, CN assets or release authority.
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
import t24_airgap_managed_cold_guard as cold
import t24_airgap_managed_applied as applied
import t24_airgap_loopback_core as loopback

NODE_DOMAIN = b"t24-node.invalid"
DIRECT_DOMAIN = b"t24-direct.invalid"
PROXY_DOMAIN = b"t24-selected.invalid"
GROUP_DOMAIN = b"t24-group.invalid"
MAX_DNS_DATAGRAM = 512
MAX_DNS_RECEIPTS = 12


def require(condition, message):
    boot.require(condition, message)


def dns_document(socks_port, dns_port):
    """One fixed synthetic node hostname, one unprivileged local UDP DNS."""
    require(type(socks_port) is int and 1023 < socks_port < 65536 and
            type(dns_port) is int and 1023 < dns_port < 65536,
            "invalid node DNS fixture port")
    document = applied.local_document(socks_port)
    document["nodes"][0]["server"] = NODE_DOMAIN.decode("ascii")
    document["dns"]["profiles"][0]["port"] = dns_port
    assert_dns_document(document, socks_port, dns_port)
    return document


def assert_dns_document(document, socks_port, dns_port):
    """Exact positive allowlist: never broaden routes, DNS or node endpoints."""
    require(type(socks_port) is int and 1023 < socks_port < 65536 and
            type(dns_port) is int and 1023 < dns_port < 65536,
            "invalid node DNS fixture port")
    expected = applied.local_document(socks_port)
    expected["nodes"][0]["server"] = NODE_DOMAIN.decode("ascii")
    expected["dns"]["profiles"][0]["port"] = dns_port
    require(type(document) is dict and document == expected,
            "unapproved node DNS declaration")


def encode_qname(name):
    require(name == NODE_DOMAIN, "unapproved DNS question name")
    labels = name.split(b".")
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def answer_node_dns(packet, expected_name=NODE_DOMAIN):
    """Parse one bounded DNS question; answer only fixed A as 127.0.0.1.

    No recursive forwarding, DNS search, alternate names or socket dial.
    Ignore only bounded optional EDNS query metadata, never serve its contents.
    """
    require(type(expected_name) is bytes and
            expected_name in (NODE_DOMAIN, DIRECT_DOMAIN, PROXY_DOMAIN, GROUP_DOMAIN),
            "unapproved DNS fixture name")
    require(type(packet) is bytes and 17 <= len(packet) <= MAX_DNS_DATAGRAM,
            "invalid DNS question bounds")
    ident, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    require(flags & 0xF800 == 0 and qd == 1 and an == 0 and ns == 0 and
            ar in (0, 1), "unapproved DNS query header")
    pos = 12
    labels = []
    for _ in range(8):
        require(pos < len(packet), "truncated DNS question name")
        length = packet[pos]
        pos += 1
        require(length <= 63, "compressed or oversized DNS question label")
        if length == 0:
            break
        require(pos + length <= len(packet),
                "truncated DNS question label")
        labels.append(packet[pos:pos + length])
        pos += length
    else:
        raise RuntimeError("DNS question label limit exceeded")
    name = b".".join(labels)
    require(name.lower() == expected_name, "unapproved DNS question name")
    require(pos + 4 <= len(packet), "truncated DNS question type")
    question_end = pos + 4
    qtype, qclass = struct.unpack("!HH", packet[pos:question_end])
    require(qclass == 1, "unapproved DNS question class")
    # EDNS0 OPT is an optional question extension, never a new lookup.
    if ar == 0:
        require(question_end == len(packet), "trailing unapproved DNS bytes")
    else:
        require(question_end + 11 <= len(packet) <= question_end + 96 and
                packet[question_end:question_end + 3] == b"\x00\x00\x29",
                "invalid DNS EDNS extension")
        rdlen = struct.unpack("!H", packet[question_end + 9:
                                           question_end + 11])[0]
        require(question_end + 11 + rdlen == len(packet),
                "invalid DNS EDNS length")
    question = packet[12:question_end]
    answers = 1 if qtype == 1 else 0
    response = (struct.pack("!6H", ident, 0x8180, 1, answers, 0, 0) +
                question)
    if answers:
        response += (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) +
                     b"\x7f\x00\x00\x01")
    require(len(response) <= MAX_DNS_DATAGRAM,
            "unbounded synthetic DNS response")
    return response, (name, qtype)


class NodeDNSResponder(socketserver.BaseRequestHandler):
    def handle(self):
        packet, udp = self.request
        try:
            require(self.client_address[0] == "127.0.0.1",
                    "non-loopback DNS client")
            reply, receipt = answer_node_dns(packet, self.server.allowed_name)
            with self.server.counter_lock:
                require(len(self.server.receipts) < MAX_DNS_RECEIPTS,
                        "unbounded local DNS attempts")
                self.server.receipts.append(receipt)
            udp.sendto(reply, self.client_address)
        except (RuntimeError, OSError, ValueError, struct.error):
            # Invalid queries are NEVER forwarded or answered from a fallback.
            with self.server.counter_lock:
                self.server.failed = True


class NodeDNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, allowed_name=NODE_DOMAIN):
        require(type(allowed_name) is bytes and
                allowed_name in (NODE_DOMAIN, DIRECT_DOMAIN, PROXY_DOMAIN, GROUP_DOMAIN),
                "unapproved DNS fixture name")
        super().__init__(address, NodeDNSResponder)
        self.allowed_name = allowed_name
        self.counter_lock = threading.Lock()
        self.receipts = []
        self.failed = False


def assert_dns_receipts(dns, expected_name=NODE_DOMAIN):
    require(type(getattr(dns, "receipts", None)) is list and
            getattr(dns, "counter_lock", None) is not None and
            getattr(dns, "failed", None) is False,
            "unhealthy local node DNS responder")
    with dns.counter_lock:
        receipts = list(dns.receipts)
    require(1 <= len(receipts) <= MAX_DNS_RECEIPTS and
            any(kind == 1 for _, kind in receipts) and
            all(type(name) is bytes and name.lower() == expected_name and
                type(kind) is int and kind in (1, 28, 65)
                for name, kind in receipts),
            "real node DNS A query was not observed")
    return len(receipts)


def probe_managed_node_dns(sock, generation, expected_pid,
                           echo_port, node, dns):
    """Genuine managed Core must query UDP DNS before Selected SOCKS connects."""
    require(type(generation) is int and generation > 0 and
            type(expected_pid) is int and expected_pid > 1 and
            type(echo_port) is int and 0 < echo_port < 65536 and
            type(node.calls) is int and node.calls == 0 and
            type(node.rejections) is int and node.rejections == 0 and
            not node.failed and not node.reject_connections,
            "invalid managed node DNS smoke fixture")
    before = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        before, generation, "running", True) == expected_pid,
        "node DNS began on changed Core")
    # Numeric-local Rule/Direct do not require outbound node DNS, and must
    # never accidentally reach Selected's synthetic SOCKS upstream.
    with dns.counter_lock:
        baseline = list(dns.receipts)
    for port in applied.MANAGED_PORTS[:2]:
        applied.probe_port(
            port, echo_port, b"node-dns-healthy-" + str(port).encode())
        with dns.counter_lock:
            unchanged = dns.receipts == baseline
        require(unchanged and node.calls == 0 and
                node.rejections == 0 and not node.failed and not dns.failed,
                "node DNS leaked into healthy Rule or Direct")
    applied.probe_port(2082, echo_port, b"node-dns-approved-echo")
    count = assert_dns_receipts(dns)
    require(node.calls == 1 and node.rejections == 0 and
            not node.failed and not node.reject_connections,
            "node DNS Selected route bypassed upstream")
    after = applied.unix_json(sock, "GET", "/v1/status")
    require(applied.committed_snapshot(
        after, generation, "running", True) == expected_pid and
        after.get("last_known_good_generation_id") ==
        before.get("last_known_good_generation_id"),
        "node DNS replaced approved Core or LKG")
    return count


def run_native_node_dns(args):
    boot.ensure_airgap(args.arch)
    require(Path(args.app).is_absolute() and os.access(args.app, os.X_OK) and
            Path(args.core).is_absolute(), "native DNS artifacts missing")
    cold.hash_pinned_core(Path(args.core), args.core_sha256)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="t24-node-dns-", dir="/work") as tmp:
        root = Path(tmp)
        env = cold.fresh_env(root, args.core)
        with (loopback.LoopbackServer(
                ("127.0.0.1", 0), loopback.LoopbackResponder) as echo,
              applied.LocalSocksServer(
                  ("127.0.0.1", 0), applied.LocalSocksNode) as node,
              NodeDNSServer(("127.0.0.1", 0)) as dns):
            echo_port = echo.server_address[1]
            node.echo_port = echo_port
            threads = [
                threading.Thread(target=server.serve_forever, daemon=True)
                for server in (echo, node, dns)
            ]
            for thread in threads:
                thread.start()
            try:
                document = dns_document(
                    node.server_address[1], dns.server_address[1])
                def work(daemon, sock, initial):
                    cold.configured_status(initial)
                    cold.configured_caps(applied.unix_json(
                        sock, "GET", "/v1/capabilities"))
                    created = applied.unix_json(
                        sock, "POST", "/v1/declaration",
                        {"expected_revision": 0,
                         "source": "lab:t24-node-dns",
                         "document": document}, expected=201)
                    require(created.get("revision") == 1 and
                            type(created.get("sha256")) is str and
                            len(created["sha256"]) == 64,
                            "node DNS declaration commit failed")
                    compiled = applied.unix_json(
                        sock, "POST", "/v1/declaration/compile",
                        {"revision": 1})
                    require(compiled.get("declaration_sha256") ==
                            created["sha256"] and
                            compiled.get("rule_set_count") == 0 and
                            type(compiled.get("config_sha256")) is str and
                            len(compiled["config_sha256"]) == 64,
                            "node DNS native compiler receipt invalid")
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
                            "node DNS generation not committed")
                    applied.committed_snapshot(
                        applied.wait_status(args.app, env, "stopped"),
                        generation, "stopped", False)
                    started = False
                    try:
                        boot.checked(
                            [args.app, "core", "start"], env, timeout=22)
                        started = True
                        running = applied.wait_status(args.app, env, "running")
                        pid = applied.committed_snapshot(
                            running, generation, "running", True)
                        applied.verify_child(pid, daemon.pid, args.core)
                        result = probe_managed_node_dns(
                            sock, generation, pid, echo_port, node, dns)
                        return result
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
                require(type(count) is int and count >= 1 and not dns.failed and
                        not node.failed and node.calls == 1 and
                        node.rejections == 0,
                        "native node DNS evidence missing after Core stop")
                cold.hash_pinned_core(Path(args.core), args.core_sha256)
            finally:
                for server in (dns, node, echo):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=5)


SAFE_CODES = {
    "invalid node DNS fixture port": "dns-node-fixture-port",
    "unapproved node DNS declaration": "dns-node-declaration",
    "unapproved DNS fixture name": "dns-node-fixture-name",
    "invalid DNS question bounds": "dns-node-question-bounds",
    "unapproved DNS query header": "dns-node-question-header",
    "unapproved DNS question name": "dns-node-question-name",
    "compressed or oversized DNS question label": "dns-node-label",
    "truncated DNS question label": "dns-node-label-short",
    "truncated DNS question name": "dns-node-name-short",
    "DNS question label limit exceeded": "dns-node-label-limit",
    "truncated DNS question type": "dns-node-type-short",
    "unapproved DNS question class": "dns-node-class",
    "trailing unapproved DNS bytes": "dns-node-trailing",
    "invalid DNS EDNS extension": "dns-node-edns",
    "invalid DNS EDNS length": "dns-node-edns-length",
    "unbounded synthetic DNS response": "dns-node-reply-size",
    "unhealthy local node DNS responder": "dns-node-responder",
    "real node DNS A query was not observed": "dns-node-query-absent",
    "invalid managed node DNS smoke fixture": "dns-node-route-invalid",
    "node DNS began on changed Core": "dns-node-core-stale",
    "node DNS leaked into healthy Rule or Direct": "dns-node-cross-route",
    "node DNS Selected route bypassed upstream": "dns-node-outbound-bypass",
    "node DNS replaced approved Core or LKG": "dns-node-core-drift",
    "native DNS artifacts missing": "dns-node-artifact",
    "node DNS declaration commit failed": "dns-node-commit",
    "node DNS native compiler receipt invalid": "dns-node-compile",
    "node DNS generation not committed": "dns-node-apply",
    "native node DNS evidence missing after Core stop": "dns-node-incomplete",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=boot.MACHINES)
    parser.add_argument("--app", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        run_native_node_dns(args)
    except (OSError, RuntimeError, ValueError, KeyError,
            struct.error, subprocess.SubprocessError) as exc:
        # Fixed, secret-free codes; never print arbitrary DNS requests or logs.
        print("T22_AIRGAP_OUTBOUND_NODE_DNS_UDP=refused", file=sys.stderr)
        print("T22_AIRGAP_NODE_DNS_FAILURE_CLASS=" +
              type(exc).__name__, file=sys.stderr)
        print("T22_AIRGAP_NODE_DNS_FAILURE_CODE=" +
              SAFE_CODES.get(str(exc), "unclassified"), file=sys.stderr)
        return 1
    print("T22_AIRGAP_OUTBOUND_NODE_DNS_UDP=ok")
    print("T22_HOSTNAME_AND_UDP_VERIFIED=false")
    print("T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false")
    print("T20_1000_RECONNECTS_VERIFIED=false")
    print("T25_72H_7D_30D_SOAK_VERIFIED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
