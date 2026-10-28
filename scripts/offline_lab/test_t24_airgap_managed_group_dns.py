#!/usr/bin/env python3
"""ADR 0178 Group DNS routed TCP + role isolation regressions (no Core)."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import struct
import threading
import unittest
from unittest import mock

import t24_airgap_loopback_core as loopback
import t24_airgap_managed_applied as applied
import t24_airgap_managed_direct_dns as direct
import t24_airgap_managed_dns as dns
import t24_airgap_managed_proxy_dns as proxy
import t24_airgap_managed_group_dns as group
import test_t24_airgap_managed_direct_dns as fake
import test_t24_airgap_managed_proxy_dns as proxytest


def node_fixture():
    node = fake.SyntheticNode()
    node.server_address = ("127.0.0.1", 41001)
    node.counter_lock = threading.Lock()
    node.destination_receipts = []
    node.echo_port = 41010
    node.http_port = 41004
    node.group_dns_port = 41005
    return node


def dns_fixtures():
    return (fake.SyntheticDNS(dns.NODE_DOMAIN, 41002),
            fake.SyntheticDNS(dns.DIRECT_DOMAIN, 41003),
            fake.SyntheticDNS(dns.PROXY_DOMAIN, 41004),
            fake.SyntheticDNS(dns.GROUP_DOMAIN, 41005))


class NativeGroupDNSTests(unittest.TestCase):
    def test_exact_custom_group_bind_and_explicit_selected_detour(self):
        doc = group.group_dns_document(41001, 41002, 41003, 41004, 41005)
        group.assert_group_document(
            doc, 41001, 41002, 41003, 41004, 41005)
        self.assertEqual(doc["dns"]["profiles"][-1], {
            "id": "group-selected-tcp", "role": "group",
            "transport": "tcp", "server": "127.0.0.1", "port": 41005,
            "detour_target": {"kind": "current_selected"},
        })
        self.assertEqual(doc["dns"]["proxy_profile_id"],
                         "proxy-selected-tcp")
        self.assertEqual(doc["routing"]["custom"], [{
            "id": "group-only-domain", "order": 1, "enabled": True,
            "target": {"kind": "direct"},
            "dns_profile_id": "group-selected-tcp",
            "match": {"op": "atom", "predicate": {
                "kind": "domain", "value": "t24-group.invalid",
            }},
        }])
        self.assertEqual(doc["routing"]["final"], {"kind": "direct"})
        for label, edit in (
            ("group remote", lambda d: d["dns"]["profiles"][-1].update(
                {"server": "8.8.8.8"})),
            ("group port 53", lambda d: d["dns"]["profiles"][-1].update(
                {"port": 53})),
            ("group role", lambda d: d["dns"]["profiles"][-1].update(
                {"role": "proxy"})),
            ("group direct detour", lambda d: d["dns"]["profiles"][-1].update(
                {"detour_target": {"kind": "direct"}})),
            ("group alternate detour", lambda d: d["dns"]["profiles"][-1].update(
                {"detour_target": {"kind": "specific_node",
                                   "profile_id": "t24", "node_id": "loop"}})),
            ("group no detour", lambda d: d["dns"]["profiles"][-1].pop(
                "detour_target")),
            ("group wrong ID", lambda d: d["routing"]["custom"][0].update(
                {"dns_profile_id": "proxy-selected-tcp"})),
            ("group wrong match", lambda d: d["routing"]["custom"][0][
                "match"]["predicate"].update({"value": "other.invalid"})),
            ("group disabled", lambda d: d["routing"]["custom"][0].update(
                {"enabled": False})),
            ("group direct route", lambda d: d["routing"]["custom"][0].update(
                {"target": {"kind": "direct"}})),
            ("group wildcard route", lambda d: d["routing"]["custom"][0][
                "match"]["predicate"].update({"kind": "domain_suffix"})),
            ("more groups", lambda d: d["routing"]["custom"].append(
                dict(d["routing"]["custom"][0]))),
            ("fallback", lambda d: d["dns"].update(
                {"fallback_profile_id": "direct-destination"})),
            ("tun", lambda d: d.update({"tun": True})),
            ("subscription", lambda d: d["routing"].update(
                {"subscription": []})),
        ):
            with self.subTest(case=label):
                mutated = json.loads(json.dumps(doc))
                edit(mutated)
                with self.assertRaises(RuntimeError):
                    group.assert_group_document(
                        mutated, 41001, 41002, 41003, 41004, 41005)
        for bad in (0, 53, 1023, 65536, True, "41001", 5.3):
            for idx in range(5):
                with self.subTest(bad=bad, index=idx):
                    ports = [41001, 41002, 41003, 41004, 41005]
                    ports[idx] = bad
                    with self.assertRaises(RuntimeError):
                        group.group_dns_document(*ports)
        with self.assertRaises(RuntimeError):
            group.group_dns_document(41001, 41002, 41003, 41004, 41004)

    def test_tcp_dns_group_name_is_strict_and_proxy_name_separate(self):
        for name in (dns.GROUP_DOMAIN, dns.PROXY_DOMAIN):
            with self.subTest(name=name):
                with proxy.ProxyTCPDNSServer(
                        ("127.0.0.1", 0), name) as srv:
                    thread = threading.Thread(
                        target=srv.serve_forever, daemon=True)
                    thread.start()
                    try:
                        packet = proxytest.question(name=name)
                        with socket.create_connection(
                                srv.server_address, timeout=2) as conn:
                            conn.settimeout(2)
                            conn.sendall(
                                struct.pack("!H", len(packet)) + packet)
                            size = struct.unpack(
                                "!H", proxytest.read_exact(conn, 2))[0]
                            self.assertTrue(
                                proxytest.read_exact(
                                    conn, size).endswith(b"\x7f\x00\x00\x01"))
                        self.assertEqual(proxy.assert_proxy_dns_receipts(
                            srv, expected_name=name), 1)
                        with socket.create_connection(
                                srv.server_address, timeout=2) as conn:
                            conn.settimeout(2)
                            other = (dns.GROUP_DOMAIN if name ==
                                     dns.PROXY_DOMAIN else dns.PROXY_DOMAIN)
                            question = proxytest.question(name=other)
                            conn.sendall(
                                struct.pack("!H", len(question)) + question)
                            self.assertEqual(conn.recv(32), b"")
                        self.assertTrue(srv.failed)
                    finally:
                        srv.shutdown()
                        thread.join(timeout=4)
        for name in (b"other.invalid", b"t24-group.invalid\x00",
                     True, 1):
            with self.subTest(name=name):
                with self.assertRaises(RuntimeError):
                    proxy.ProxyTCPDNSServer(("127.0.0.1", 0), name)

    def test_group_sock5_client_transmits_raw_domain_without_system_dns(self):
        class Conn:
            def __init__(self):
                self.data = bytearray(
                    b"\x05\x00" +
                    b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                    struct.pack("!H", 41010) +
                    loopback.REPLY_PREFIX + b"group-test")
                self.sent = []
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def settimeout(self, timeout):
                self.timeout = timeout
            def sendall(self, data):
                self.sent.append(data)
            def recv(self, n):
                result = bytes(self.data[:n])
                del self.data[:n]
                return result
        conn = Conn()
        with mock.patch.object(
                group.socket, "create_connection",
                return_value=conn) as dial:
            group.probe_group_domain(41010, b"group-test")
        dial.assert_called_once_with(("127.0.0.1", 2080), timeout=4)
        self.assertEqual(conn.sent, [
            b"\x05\x01\x00",
            b"\x05\x01\x00\x03" +
            bytes([len(group.GROUP_DOMAIN)]) +
            group.GROUP_DOMAIN + struct.pack("!H", 41010),
            b"group-test",
        ])
        for port, payload in ((0, b"okay"), (53, b"okay"),
                              (41010, b""), (41010, "unsafe")):
            with self.subTest(port=port, payload=payload):
                with mock.patch.object(
                        group.socket, "create_connection") as dial:
                    with self.assertRaises(RuntimeError):
                        group.probe_group_domain(port, payload)
                    dial.assert_not_called()

    def test_upstream_receipt_requires_group_dns_detour_not_group_app(self):
        node = node_fixture()
        # Matching group application is DIRECT. Its Group DNS transport
        # must nonetheless connect through Selected to the Group TCP port.
        node.destination_receipts.append((None, "127.0.0.1", 41005))
        node.calls = 1
        self.assertEqual(group.verify_upstream(
            node, 41010, 41004, 41005, True, False), (1, 1, 0))
        node.destination_receipts.extend([
            (None, "127.0.0.1", 41004),
            (group.PROXY_DOMAIN, "127.0.0.1", 41010)])
        node.hostname_requests.append((group.PROXY_DOMAIN, 41010))
        node.calls = 3
        self.assertEqual(group.verify_upstream(
            node, 41010, 41004, 41005, True, True), (3, 1, 1))
        for defect in ("wrong-port", "external-address", "missing-group",
                       "missing-proxy", "extra-group-app", "duplicate-proxy-app",
                       "node-denied", "node-failed", "forged-hostname"):
            with self.subTest(defect=defect):
                another = node_fixture()
                another.destination_receipts = list(node.destination_receipts)
                another.hostname_requests = list(node.hostname_requests)
                another.calls = node.calls
                if defect == "wrong-port":
                    another.destination_receipts[0] = (
                        None, "127.0.0.1", 53)
                elif defect == "external-address":
                    another.destination_receipts[0] = (
                        None, "8.8.8.8", 41005)
                elif defect == "missing-group":
                    another.destination_receipts.pop(0)
                    another.calls -= 1
                elif defect == "missing-proxy":
                    another.destination_receipts.pop(1)
                    another.calls -= 1
                elif defect == "extra-group-app":
                    another.destination_receipts.insert(
                        1, (None, "127.0.0.1", 41010))
                    another.calls += 1
                elif defect == "duplicate-proxy-app":
                    another.destination_receipts.append(
                        (group.PROXY_DOMAIN, "127.0.0.1", 41010))
                    another.hostname_requests.append(
                        (group.PROXY_DOMAIN, 41010))
                    another.calls += 1
                elif defect == "node-denied":
                    another.rejections = 1
                elif defect == "node-failed":
                    another.failed = True
                elif defect == "forged-hostname":
                    another.hostname_requests[0] = (b"bad.invalid", 41010)
                with self.assertRaises(RuntimeError):
                    group.verify_upstream(
                        another, 41010, 41004, 41005, True, True)

    def test_managed_group_route_checks_both_resolvers_with_core_identity(self):
        def scenario(defect=None):
            node = node_fixture()
            nd, dd, pd, gd = dns_fixtures()
            initial = fake.running_status(
                pid=999 if defect == "stale-core" else 222)
            ending = fake.running_status(
                pid=999 if defect == "core-replaced" else 222,
                lkg=9 if defect == "lkg-drift" else 7)
            def direct_control(port, _echo, _payload):
                if port == 2081:
                    dd.receipts.append((dns.DIRECT_DOMAIN, 1))
                    if defect == "direct-selected-leak":
                        node.calls += 1
                    if defect == "direct-proxy-leak":
                        pd.receipts.append((dns.PROXY_DOMAIN, 1))
            def group_control(_port, _payload):
                gd.receipts.append((
                    b"other.invalid" if defect == "wrong-group-name"
                    else dns.GROUP_DOMAIN,
                    28 if defect == "no-group-A" else 1))
                if defect == "group-used-proxy":
                    pd.receipts.append((dns.PROXY_DOMAIN, 1))
                if defect == "group-used-node":
                    nd.receipts.append((dns.NODE_DOMAIN, 1))
                if defect == "group-used-direct":
                    dd.receipts.append((dns.DIRECT_DOMAIN, 1))
                if defect != "group-upstream-bypass":
                    node.destination_receipts.append(
                        (None, "127.0.0.1", 41005))
                    node.calls += 1
            def selected_control(_port, _payload):
                pd.receipts.append((dns.PROXY_DOMAIN, 1))
                node.destination_receipts.extend([
                    (None, "127.0.0.1", 41004),
                    (group.PROXY_DOMAIN, "127.0.0.1", 41010)])
                node.hostname_requests.append((group.PROXY_DOMAIN, 41010))
                node.calls += 2
                if defect == "proxy-used-group":
                    gd.receipts.append((dns.GROUP_DOMAIN, 1))
                if defect == "proxy-used-direct":
                    dd.receipts.append((dns.DIRECT_DOMAIN, 1))
                if defect == "proxy-upstream-bypass":
                    node.destination_receipts.pop(1)
                    node.calls -= 1
                if defect == "proxy-denied":
                    node.rejections = 1
            with (mock.patch.object(
                    applied, "unix_json", side_effect=[initial, ending]),
                  mock.patch.object(
                      direct, "probe_direct_domain_socks",
                      side_effect=direct_control),
                  mock.patch.object(
                      group, "probe_group_domain",
                      side_effect=group_control),
                  mock.patch.object(
                      applied, "probe_selected_socks_domain",
                      side_effect=selected_control)):
                return group.audit_managed_group_dns(
                    "/sock", 7, 222, 41010, node, nd, dd, pd, gd)
        self.assertEqual(scenario(), (1, 1, 1))
        for defect in ("stale-core", "core-replaced", "lkg-drift",
                       "direct-selected-leak", "direct-proxy-leak",
                       "wrong-group-name", "no-group-A", "group-used-proxy",
                       "group-used-node", "group-used-direct",
                       "group-upstream-bypass", "proxy-used-group",
                       "proxy-used-direct", "proxy-upstream-bypass",
                       "proxy-denied"):
            with self.subTest(defect=defect):
                with self.assertRaises(RuntimeError):
                    scenario(defect)

    def test_workflow_eight_independent_native_containers(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/core-provenance.yml").read_text()
        for item in ("docker run --rm --pull never",
                     "--network none --cap-drop ALL",
                     "--user 10001:10001 --read-only"):
            self.assertEqual(workflow.count(item), 8)
        self.assertIn("t24_airgap_managed_group_dns.py", workflow)
        self.assertEqual(group.SAFE_CODES[
            "Group DNS Direct application leaked into Selected SOCKS"],
            "group-dns-app-leak")
        self.assertNotIn("password", group.SAFE_CODES)


if __name__ == "__main__":
    unittest.main()
