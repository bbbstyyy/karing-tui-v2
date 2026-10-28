#!/usr/bin/env python3
"""ADR 0176 Direct destination UDP DNS regression tests (no Core/Docker)."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import struct
import threading
import unittest
from unittest import mock

import t24_airgap_managed_applied as applied
import t24_airgap_managed_direct_dns as direct
import t24_airgap_managed_dns as node_dns
import t24_airgap_loopback_core as loopback


class SyntheticDNS:
    def __init__(self, name, port):
        self.allowed_name = name
        self.server_address = ("127.0.0.1", port)
        self.receipts = []
        self.counter_lock = threading.Lock()
        self.failed = False


class SyntheticNode:
    def __init__(self):
        self.calls = 0
        self.rejections = 0
        self.failed = False
        self.reject_connections = False
        self.hostname_requests = []
        self.rejected_hostname_requests = []


def running_status(pid=222, generation=7, lkg=7):
    return {
        "api_version": "v1", "core_configured": True,
        "core_desired_state": "running", "core_state": "running",
        "recovery_required": False, "core_circuit_open": False,
        "config_revision": 1, "declaration_revision": 1,
        "applied_generation_id": generation,
        "last_known_good_generation_id": lkg, "core_pid": pid,
    }


class DirectDNSPolicyTests(unittest.TestCase):
    def test_exact_direct_profile_and_independent_server_roles(self):
        doc = direct.direct_dns_document(41001, 41002, 41003)
        self.assertEqual(doc["nodes"][0]["server"], "127.0.0.1")
        self.assertEqual(doc["dns"], {
            "profiles": [
                {"id": "local-only", "role": "outbound",
                 "transport": "udp", "server": "127.0.0.1",
                 "port": 41002},
                {"id": "direct-destination", "role": "direct",
                 "transport": "udp", "server": "127.0.0.1",
                 "port": 41003},
            ],
            "outbound_profile_id": "local-only",
            "direct_profile_id": "direct-destination",
        })
        self.assertEqual(doc["routing"]["final"], {"kind": "direct"})
        self.assertEqual(doc["routing"]["custom"], [])
        direct.assert_direct_dns_document(doc, 41001, 41002, 41003)
        for name, mutate in (
            ("external node", lambda d: d["nodes"][0].update(
                {"server": "public.example.net"})),
            ("external DNS", lambda d: d["dns"]["profiles"][1].update(
                {"server": "8.8.8.8"})),
            ("switch direct to proxy", lambda d: d["dns"]["profiles"][1].update(
                {"role": "proxy"})),
            ("swap DNS roles", lambda d: d["dns"].update(
                {"direct_profile_id": "local-only"})),
            ("fallback", lambda d: d["dns"].update(
                {"fallback_profile_id": "direct-destination"})),
            ("detour", lambda d: d["dns"]["profiles"][1].update(
                {"detour_target": {"kind": "current_selected"}})),
            ("privileged port", lambda d: d["dns"]["profiles"][1].update(
                {"port": 53})),
            ("tun", lambda d: d.update({"tun": True})),
            ("extra route", lambda d: d["routing"]["custom"].append(
                {"id": "bad", "target": {"kind": "current_selected"}})),
        ):
            with self.subTest(name=name):
                changed = json.loads(json.dumps(doc))
                mutate(changed)
                with self.assertRaises(RuntimeError):
                    direct.assert_direct_dns_document(
                        changed, 41001, 41002, 41003)
        for port in (0, 53, 1023, 65536, True, "41001"):
            with self.subTest(port=port):
                with self.assertRaises(RuntimeError):
                    direct.direct_dns_document(port, 41002, 41003)
                with self.assertRaises(RuntimeError):
                    direct.direct_dns_document(41001, port, 41003)
                with self.assertRaises(RuntimeError):
                    direct.direct_dns_document(41001, 41002, port)
        with self.assertRaises(RuntimeError):
            direct.direct_dns_document(41001, 41002, 41002)

    def test_dns_responder_is_exact_name_and_never_forwards(self):
        for name in (node_dns.NODE_DOMAIN, direct.DIRECT_DOMAIN):
            with self.subTest(name=name):
                with node_dns.NodeDNSServer(
                        ("127.0.0.1", 0), name) as server:
                    self.assertEqual(server.allowed_name, name)
                    self.assertEqual(server.receipts, [])
        for other in (b"random.invalid", b"example.com", True,
                      b"t24-node.invalid\x00"):
            with self.subTest(name=other):
                with self.assertRaises(RuntimeError):
                    node_dns.NodeDNSServer(("127.0.0.1", 0), other)
        labels = direct.DIRECT_DOMAIN.split(b".")
        question = (struct.pack("!6H", 41, 0x0100, 1, 0, 0, 0) +
                    b"".join(bytes([len(x)]) + x for x in labels) +
                    b"\x00\x00\x01\x00\x01")
        response, receipt = node_dns.answer_node_dns(
            question, direct.DIRECT_DOMAIN)
        self.assertEqual(receipt, (direct.DIRECT_DOMAIN, 1))
        self.assertTrue(response.endswith(b"\x7f\x00\x00\x01"))
        with self.assertRaises(RuntimeError):
            node_dns.answer_node_dns(question)
        with self.assertRaises(RuntimeError):
            node_dns.answer_node_dns(question, b"unapproved.invalid")

    def test_direct_domain_client_uses_exact_atyp3_bytes_no_dns_lookup(self):
        response = (b"\x05\x00" +
                    b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                    struct.pack("!H", 41001) +
                    loopback.REPLY_PREFIX + b"direct-dns-test")
        class Conn:
            def __init__(self):
                self.buf = bytearray(response)
                self.writes = []
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.closed = True
            def settimeout(self, n):
                self.timeout = n
            def sendall(self, data):
                self.writes.append(data)
            def recv(self, n):
                item = bytes(self.buf[:n])
                del self.buf[:n]
                return item
        conn = Conn()
        with mock.patch.object(
                direct.socket, "create_connection", return_value=conn) as dial:
            direct.probe_direct_domain_socks(
                2080, 41001, b"direct-dns-test")
        dial.assert_called_once_with(("127.0.0.1", 2080), timeout=4)
        self.assertEqual(conn.timeout, 4)
        self.assertEqual(conn.writes, [
            b"\x05\x01\x00",
            b"\x05\x01\x00\x03" +
            bytes([len(direct.DIRECT_DOMAIN)]) +
            direct.DIRECT_DOMAIN + struct.pack("!H", 41001),
            b"direct-dns-test",
        ])
        self.assertTrue(conn.closed)
        for port, echo, payload in (
            (2082, 41001, b"safe"),
            (2080, 0, b"safe"),
            (True, 41001, b"safe"),
            (2081, 41001, b""),
            (2081, 41001, "unsafe"),
        ):
            with self.subTest(args=(port, echo, payload)):
                with mock.patch.object(
                        direct.socket, "create_connection") as dial:
                    with self.assertRaises(RuntimeError):
                        direct.probe_direct_domain_socks(
                            port, echo, payload)
                    dial.assert_not_called()

    def test_direct_route_audits_real_receipt_and_numeric_selected_isolation(self):
        outbound = SyntheticDNS(node_dns.NODE_DOMAIN, 41002)
        resolver = SyntheticDNS(direct.DIRECT_DOMAIN, 41003)
        node = SyntheticNode()
        visited = []
        status = running_status()
        def direct_client(port, echo, payload):
            visited.append(port)
            self.assertEqual(echo, 41001)
            self.assertEqual(payload,
                             b"direct-dns-real-" + str(port).encode())
            if port == 2080:
                with resolver.counter_lock:
                    resolver.receipts.extend([
                        (direct.DIRECT_DOMAIN, 28),
                        (direct.DIRECT_DOMAIN, 1)])
        def selected_client(port, echo, payload):
            self.assertEqual((port, echo, payload),
                             (2082, 41001, b"direct-dns-selected-numeric"))
            node.calls += 1
        with (mock.patch.object(applied, "unix_json",
                                return_value=status) as api,
              mock.patch.object(direct, "probe_direct_domain_socks",
                                side_effect=direct_client) as domain,
              mock.patch.object(applied, "probe_port",
                                side_effect=selected_client) as selected):
            self.assertEqual(direct.audit_managed_direct_dns(
                "/sock", 7, 222, 41001, node, outbound, resolver), 2)
        self.assertEqual(visited, [2080, 2081])
        self.assertEqual(domain.call_count, 2)
        selected.assert_called_once()
        self.assertEqual(api.call_count, 2)
        self.assertEqual(node.calls, 1)
        self.assertEqual(outbound.receipts, [])

    def test_direct_route_rejects_cross_role_or_false_evidence(self):
        for defect in (
            "outbound-query", "missing-A", "missing-receipt",
            "wrong-receipt-name", "direct-bypass", "new-rejection",
            "selected-queries-direct", "selected-queries-outbound",
            "selected-bypass", "wrong-core-before", "wrong-core-after",
            "wrong-LKG", "node-failure", "dns-failure",
        ):
            with self.subTest(defect=defect):
                outbound = SyntheticDNS(node_dns.NODE_DOMAIN, 41002)
                resolver = SyntheticDNS(direct.DIRECT_DOMAIN, 41003)
                node = SyntheticNode()
                before = running_status(
                    pid=333 if defect == "wrong-core-before" else 222)
                after = running_status(
                    pid=333 if defect == "wrong-core-after" else 222,
                    lkg=9 if defect == "wrong-LKG" else 7)
                def domain_client(port, _echo, _payload):
                    if port == 2080:
                        if defect == "direct-bypass":
                            node.calls += 1
                        if defect == "new-rejection":
                            node.rejections += 1
                        if defect == "node-failure":
                            node.failed = True
                        if defect == "dns-failure":
                            resolver.failed = True
                        if defect == "outbound-query":
                            outbound.receipts.append(
                                (node_dns.NODE_DOMAIN, 1))
                        if defect != "missing-receipt":
                            name = (b"wrong.invalid" if
                                    defect == "wrong-receipt-name"
                                    else direct.DIRECT_DOMAIN)
                            resolver.receipts.append(
                                (name, 28 if defect == "missing-A" else 1))
                def numeric_client(*_args):
                    if defect == "selected-queries-direct":
                        resolver.receipts.append((direct.DIRECT_DOMAIN, 1))
                    if defect == "selected-queries-outbound":
                        outbound.receipts.append((node_dns.NODE_DOMAIN, 1))
                    if defect != "selected-bypass":
                        node.calls += 1
                with (mock.patch.object(applied, "unix_json",
                                        side_effect=[before, after]),
                      mock.patch.object(direct, "probe_direct_domain_socks",
                                        side_effect=domain_client),
                      mock.patch.object(applied, "probe_port",
                                        side_effect=numeric_client)):
                    with self.assertRaises(RuntimeError):
                        direct.audit_managed_direct_dns(
                            "/sock", 7, 222, 41001, node,
                            outbound, resolver)
        for msg, code in (
            ("Direct destination DNS used Outbound/Node DNS",
             "direct-dns-role-bypass"),
            ("Direct DNS Selected control did not use exact upstream",
             "direct-dns-selected"),
            ("Direct DNS replaced running Core or LKG",
             "direct-dns-core-drift"),
        ):
            self.assertEqual(direct.SAFE_CODES[msg], code)
        self.assertNotIn("credentials", direct.SAFE_CODES)

    def test_workflow_keeps_seven_native_airgaps_and_no_capabilities(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/core-provenance.yml").read_text()
        for needle in (
            "docker run --rm --pull never",
            "--network none --cap-drop ALL",
            "--user 10001:10001 --read-only",
        ):
            self.assertEqual(workflow.count(needle), 7)
        self.assertIn("t24_airgap_managed_direct_dns.py", workflow)
        self.assertIn("t24_airgap_managed_dns.py", workflow)


if __name__ == "__main__":
    unittest.main()
