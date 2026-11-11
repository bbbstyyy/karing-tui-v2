#!/usr/bin/env python3
"""ADR 0175 strict offline UDP DNS and managed-node route tests (no Core)."""
from __future__ import annotations

import json
import socket
import struct
import threading
import unittest
from unittest import mock

import t24_airgap_managed_dns as dns
import t24_airgap_managed_applied as applied
import t24_airgap_loopback_core as loopback


def question(name=dns.NODE_DOMAIN, qtype=1, flags=0x0100, ar=0):
    labels = b"".join(bytes([len(x)]) + x for x in name.split(b"."))
    packet = (struct.pack("!6H", 0x4A0F, flags, 1, 0, 0, ar) +
              labels + b"\x00" + struct.pack("!HH", qtype, 1))
    if ar:
        packet += b"\x00\x00\x29" + struct.pack("!H", 1232) + b"\x00" * 4 + b"\x00\x00"
    return packet


class NativeNodeDNSTests(unittest.TestCase):
    def test_exact_document_never_adds_public_resolvers_or_privileges(self):
        doc = dns.dns_document(41001, 41002)
        self.assertEqual(doc["nodes"][0]["server"], "t24-node.invalid")
        self.assertEqual(doc["dns"]["profiles"], [{
            "id": "local-only", "role": "outbound", "transport": "udp",
            "server": "127.0.0.1", "port": 41002}])
        self.assertEqual(doc["routing"]["final"], {"kind": "direct"})
        dns.assert_dns_document(doc, 41001, 41002)
        for name, change in (
            ("public resolver", lambda d: d["dns"]["profiles"][0].update(
                {"server": "1.1.1.1"})),
            ("public node", lambda d: d["nodes"][0].update(
                {"server": "remote.example.net"})),
            ("DNS role", lambda d: d["dns"]["profiles"][0].update(
                {"role": "proxy"})),
            ("DNS port", lambda d: d["dns"]["profiles"][0].update(
                {"port": 53})),
            ("DNS detour", lambda d: d["dns"]["profiles"][0].update(
                {"detour": "direct"})),
            ("fallback", lambda d: d["dns"].update(
                {"fallback_profile_id": "local-only"})),
            ("system tun", lambda d: d.update({"tun": True})),
            ("final proxy", lambda d: d["routing"].update(
                {"final": {"kind": "current_selected"}})),
        ):
            with self.subTest(name=name):
                tampered = json.loads(json.dumps(doc))
                change(tampered)
                with self.assertRaises(RuntimeError):
                    dns.assert_dns_document(tampered, 41001, 41002)
        for port in (0, 53, 1023, 65536, True, "41001"):
            with self.subTest(port=port):
                with self.assertRaises(RuntimeError):
                    dns.dns_document(port, 41002)
                with self.assertRaises(RuntimeError):
                    dns.dns_document(41001, port)

    def test_dns_responses_are_bounded_and_fixed_local_A_only(self):
        for kind in (1, 28, 65):
            with self.subTest(type=kind):
                packet = question(qtype=kind)
                answer, receipt = dns.answer_node_dns(packet)
                self.assertEqual(receipt, (dns.NODE_DOMAIN, kind))
                self.assertEqual(answer[:2], packet[:2])
                self.assertEqual(struct.unpack("!HHHHH", answer[2:12]),
                                 (0x8180, 1, 1 if kind == 1 else 0, 0, 0))
                self.assertIn(packet[12:], answer)
                if kind == 1:
                    self.assertTrue(answer.endswith(
                        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) +
                        b"\x7f\x00\x00\x01"))
                else:
                    self.assertEqual(answer, answer[:12] + packet[12:])
        with_edns = question(ar=1)
        answer, receipt = dns.answer_node_dns(with_edns)
        self.assertEqual(receipt, (dns.NODE_DOMAIN, 1))
        self.assertTrue(answer.endswith(b"\x7f\x00\x00\x01"))
        self.assertEqual(struct.unpack("!H", answer[10:12])[0], 0)
        mixed_case = question(name=b"T24-NODE.Invalid")
        response, actual = dns.answer_node_dns(mixed_case)
        self.assertEqual(actual, (b"T24-NODE.Invalid", 1))
        self.assertIn(mixed_case[12:], response)

    def test_dns_question_rejects_wrong_target_and_invalid_wire_without_answer(self):
        correct = question()
        for name, invalid in (
            ("external name", question(name=b"outside.test")),
            ("wrong reserved name", question(name=b"t24-else.invalid")),
            ("client response", question(flags=0x8180)),
            ("alternate opcode", question(flags=0x1100)),
            ("two questions", correct[:4] + b"\x00\x02" + correct[6:]),
            ("answer spoof", correct[:6] + b"\x00\x01" + correct[8:]),
            ("bad class", correct[:-2] + b"\x00\x03"),
            ("truncated type", correct[:-1]),
            ("trailing bytes", correct + b"bad"),
            ("truncated label", correct[:17]),
            ("compressed label", correct[:12] + b"\xc0\x0c" + correct[-4:]),
            ("too many labels", correct[:12] + b"\x01x" * 8 +
             b"\x00\x00\x01\x00\x01"),
            ("missing EDNS", question(ar=1)[:-11]),
            ("bad EDNS type", question(ar=1)[:-10] + b"\x30" +
             question(ar=1)[-9:]),
            ("oversize", correct + b"x" * 512),
        ):
            with self.subTest(name=name):
                with self.assertRaises(RuntimeError):
                    dns.answer_node_dns(invalid)

    def test_real_udp_server_local_A_and_fail_closed_unapproved_name(self):
        with dns.NodeDNSServer(("127.0.0.1", 0)) as server:
            self.assertGreater(server.server_address[1], 1023)
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(question(), server.server_address)
                    answer, address = client.recvfrom(512)
                    self.assertEqual(address[0], "127.0.0.1")
                    self.assertTrue(answer.endswith(b"\x7f\x00\x00\x01"))
                    self.assertEqual(dns.assert_dns_receipts(server), 1)
                    client.sendto(question(name=b"outside.test"),
                                  server.server_address)
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(512)
                with server.counter_lock:
                    self.assertEqual(server.receipts, [(dns.NODE_DOMAIN, 1)])
                    self.assertTrue(server.failed)
                with self.assertRaises(RuntimeError):
                    dns.assert_dns_receipts(server)
            finally:
                server.shutdown()
                thread.join(timeout=4)

    def test_route_audits_healthy_inbounds_dns_receipt_and_core_identity(self):
        class Node:
            def __init__(self):
                self.calls = 0
                self.rejections = 0
                self.failed = False
                self.reject_connections = False
        class FakeDNS:
            def __init__(self):
                self.receipts = []
                self.counter_lock = threading.Lock()
                self.failed = False
        node, server = Node(), FakeDNS()
        status = {
            "api_version": "v1", "core_configured": True,
            "core_desired_state": "running", "core_state": "running",
            "recovery_required": False, "core_circuit_open": False,
            "config_revision": 1, "declaration_revision": 1,
            "applied_generation_id": 7, "last_known_good_generation_id": 7,
            "core_pid": 222,
        }
        calls = []
        def success(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            calls.append(port)
            if port == 2082:
                self.assertEqual(payload, b"node-dns-approved-echo")
                with server.counter_lock:
                    server.receipts.extend([
                        (dns.NODE_DOMAIN, 28), (dns.NODE_DOMAIN, 1)])
                node.calls += 1
        with (mock.patch.object(applied, "unix_json", return_value=status) as api,
              mock.patch.object(applied, "probe_port",
                                side_effect=success) as proxy):
            self.assertEqual(dns.probe_managed_node_dns(
                "/sock", 7, 222, 41001, node, server), 2)
        self.assertEqual(calls, [2080, 2081, 2082])
        self.assertEqual(api.call_count, 2)
        self.assertEqual(proxy.call_count, 3)
        self.assertEqual(node.calls, 1)
        for defect in ("wrong-name", "missing-A", "missing-DNS", "direct-bypass",
                       "new-rejection", "stale-core", "replaced-core",
                       "changed-LKG", "cross-route"):
            with self.subTest(defect=defect):
                node, server = Node(), FakeDNS()
                old = dict(status)
                changed = dict(status)
                if defect == "stale-core":
                    old["core_pid"] = 999
                if defect == "replaced-core":
                    changed["core_pid"] = 999
                if defect == "changed-LKG":
                    changed["last_known_good_generation_id"] = 9
                def corrupted(port, echo_port, payload):
                    if port == 2080 and defect == "cross-route":
                        node.calls += 1
                    if port == 2082:
                        if defect != "direct-bypass":
                            node.calls += 1
                        if defect == "new-rejection":
                            node.rejections += 1
                        if defect != "missing-DNS":
                            name = (b"outside.invalid" if
                                    defect == "wrong-name" else dns.NODE_DOMAIN)
                            kind = 28 if defect == "missing-A" else 1
                            server.receipts.append((name, kind))
                replies = [old] if defect == "stale-core" else [old, changed]
                with (mock.patch.object(applied, "unix_json",
                                        side_effect=replies),
                      mock.patch.object(applied, "probe_port",
                                        side_effect=corrupted)):
                    with self.assertRaises(RuntimeError):
                        dns.probe_managed_node_dns(
                            "/sock", 7, 222, 41001, node, server)
        self.assertEqual(dns.SAFE_CODES[
            "real node DNS A query was not observed"], "dns-node-query-absent")
        self.assertNotIn("private-secret", dns.SAFE_CODES)


if __name__ == "__main__":
    unittest.main()
