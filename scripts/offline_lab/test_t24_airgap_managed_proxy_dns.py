#!/usr/bin/env python3
"""ADR 0177 Proxy TCP DNS over Selected SOCKS detour: strict offline tests."""
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
import t24_airgap_managed_dns as dns
import t24_airgap_managed_proxy_dns as proxy
import test_t24_airgap_managed_direct_dns as fake


def question(name=proxy.PROXY_DOMAIN, kind=1, qid=0x73):
    labels = b"".join(bytes([len(x)]) + x for x in name.split(b"."))
    return (struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0) +
            labels + b"\x00" + struct.pack("!HH", kind, 1))


def read_exact(conn, count):
    result = b""
    while len(result) < count:
        chunk = conn.recv(count - len(result))
        if not chunk:
            raise RuntimeError("unexpected TCP DNS EOF")
        result += chunk
    return result


class NativeProxyDNSTests(unittest.TestCase):
    def test_document_restricts_selected_detour_to_only_local_proxy_dns(self):
        doc = proxy.proxy_dns_document(41001, 41002, 41003, 41004)
        self.assertEqual(doc["nodes"][0]["server"], "127.0.0.1")
        self.assertEqual(doc["routing"]["final"], {"kind": "direct"})
        self.assertEqual(doc["routing"]["custom"], [])
        self.assertEqual(doc["dns"]["proxy_profile_id"],
                         "proxy-selected-tcp")
        self.assertEqual(doc["dns"]["direct_profile_id"],
                         "direct-destination")
        self.assertEqual(doc["dns"]["outbound_profile_id"], "local-only")
        self.assertEqual(doc["dns"]["profiles"][-1], {
            "id": "proxy-selected-tcp", "role": "proxy",
            "transport": "tcp", "server": "127.0.0.1", "port": 41004,
        })
        proxy.assert_proxy_dns_document(doc, 41001, 41002, 41003, 41004)
        for name, mutator in (
            ("public proxy resolver", lambda d: d["dns"]["profiles"][-1].update(
                {"server": "9.9.9.9"})),
            ("udp proxy resolver", lambda d: d["dns"]["profiles"][-1].update(
                {"transport": "udp"})),
            ("wrong DNS role", lambda d: d["dns"]["profiles"][-1].update(
                {"role": "direct"})),
            ("explicit detour", lambda d: d["dns"]["profiles"][-1].update(
                {"detour_target": {"kind": "direct"}})),
            ("dns bypass", lambda d: d["dns"].update(
                {"proxy_profile_id": "direct-destination"})),
            ("DNS fallback", lambda d: d["dns"].update(
                {"fallback_profile_id": "local-only"})),
            ("selected node remote", lambda d: d["nodes"][0].update(
                {"server": "node.example.com"})),
            ("custom proxy rule", lambda d: d["routing"]["custom"].append(
                {"id": "unapproved", "target": {"kind": "current_selected"}})),
            ("tun", lambda d: d.update({"tun": True})),
        ):
            with self.subTest(name=name):
                tampered = json.loads(json.dumps(doc))
                mutator(tampered)
                with self.assertRaises(RuntimeError):
                    proxy.assert_proxy_dns_document(
                        tampered, 41001, 41002, 41003, 41004)
        for bad_port in (0, 53, 1023, 65536, True, "41001", 41001.2):
            with self.subTest(port=bad_port):
                for index in range(4):
                    ports = [41001, 41002, 41003, 41004]
                    ports[index] = bad_port
                    with self.assertRaises(RuntimeError):
                        proxy.proxy_dns_document(*ports)
        for ports in ((41001, 41002, 41002, 41004),
                      (41004, 41002, 41003, 41004)):
            with self.subTest(ports=ports):
                with self.assertRaises(RuntimeError):
                    proxy.proxy_dns_document(*ports)

    def test_tcp_dns_responder_real_frames_nodata_and_no_remote_fallback(self):
        with proxy.ProxyTCPDNSServer(("127.0.0.1", 0)) as server:
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            try:
                self.assertGreater(server.server_address[1], 1023)
                with socket.create_connection(server.server_address,
                                              timeout=2) as client:
                    client.settimeout(2)
                    for kind in (1, 28, 65):
                        q = question(kind=kind, qid=0x72 + kind)
                        client.sendall(struct.pack("!H", len(q)) + q)
                        size = struct.unpack("!H",
                                             read_exact(client, 2))[0]
                        reply = read_exact(client, size)
                        self.assertEqual(reply[:2], q[:2])
                        self.assertEqual(struct.unpack(
                            "!H", reply[6:8])[0],
                            1 if kind == 1 else 0)
                        if kind == 1:
                            self.assertTrue(reply.endswith(
                                b"\x7f\x00\x00\x01"))
                        else:
                            self.assertEqual(reply[12:], q[12:])
                self.assertEqual(proxy.assert_proxy_dns_receipts(server), 3)
                self.assertFalse(server.failed)
                with socket.create_connection(server.server_address,
                                              timeout=2) as bad:
                    bad.settimeout(2)
                    unexpected = question(b"outside.invalid")
                    bad.sendall(struct.pack("!H", len(unexpected)) +
                                unexpected)
                    self.assertEqual(bad.recv(20), b"")
                self.assertTrue(server.failed)
                with self.assertRaises(RuntimeError):
                    proxy.assert_proxy_dns_receipts(server)
            finally:
                server.shutdown()
                thread.join(timeout=4)

        for addr in (("0.0.0.0", 0), ("127.0.0.1", 53),
                     ("127.0.0.1", "0")):
            with self.subTest(address=addr):
                with self.assertRaises(RuntimeError):
                    proxy.ProxyTCPDNSServer(addr)

    def test_tcp_dns_rejects_oversized_and_partial_queries(self):
        for body in (b"\x02\x01", b"\x00\x01" + b"x",
                     struct.pack("!H", len(question()) + 2) + question()):
            with self.subTest(frame=body[:8]):
                with proxy.ProxyTCPDNSServer(("127.0.0.1", 0)) as server:
                    thread = threading.Thread(
                        target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        with socket.create_connection(
                                server.server_address, timeout=2) as client:
                            client.sendall(body)
                            client.shutdown(socket.SHUT_WR)
                            client.settimeout(2)
                            self.assertEqual(client.recv(30), b"")
                        self.assertTrue(server.failed)
                        self.assertFalse(server.receipts)
                    finally:
                        server.shutdown()
                        thread.join(timeout=4)

    def test_actual_core_route_audit_accepts_only_proxy_tcp_selected_evidence(self):
        outbound = fake.SyntheticDNS(dns.NODE_DOMAIN, 41002)
        direct_dns = fake.SyntheticDNS(dns.DIRECT_DOMAIN, 41003)
        tcp = fake.SyntheticDNS(proxy.PROXY_DOMAIN, 41004)
        node = fake.SyntheticNode()
        node.destination_receipts = []
        node.http_port = 41004
        node.echo_port = 41001
        node.counter_lock = threading.Lock()
        before = fake.running_status()
        controls = []
        def direct_control(port, echo, payload):
            self.assertEqual(echo, 41001)
            controls.append(port)
            self.assertEqual(payload,
                             b"proxy-dns-direct-control-" +
                             str(port).encode("ascii"))
            if port == 2080:
                with direct_dns.counter_lock:
                    direct_dns.receipts.extend([
                        (dns.DIRECT_DOMAIN, 28),
                        (dns.DIRECT_DOMAIN, 1)])
        def selected_client(echo, payload):
            self.assertEqual((echo, payload),
                             (41001, b"proxy-dns-selected-tunnel"))
            with tcp.counter_lock:
                tcp.receipts.extend([
                    (proxy.PROXY_DOMAIN, 28),
                    (proxy.PROXY_DOMAIN, 1)])
            with node.counter_lock:
                node.destination_receipts.extend([
                    (None, "127.0.0.1", 41004),
                    (proxy.PROXY_DOMAIN, "127.0.0.1", 41001),
                ])
                node.hostname_requests.append((proxy.PROXY_DOMAIN, 41001))
                node.calls = 2
        with (mock.patch.object(applied, "unix_json",
                                return_value=before) as api,
              mock.patch.object(direct, "probe_direct_domain_socks",
                                side_effect=direct_control) as ctrl,
              mock.patch.object(applied, "probe_selected_socks_domain",
                                side_effect=selected_client) as selected):
            self.assertEqual(proxy.audit_managed_proxy_dns(
                "/sock", 7, 222, 41001, node, outbound,
                direct_dns, tcp), (2, 2))
        self.assertEqual(controls, [2080, 2081])
        self.assertEqual(api.call_count, 2)
        self.assertEqual(ctrl.call_count, 2)
        selected.assert_called_once()
        self.assertEqual(node.calls, 2)
        self.assertFalse(outbound.receipts)

    def test_failure_isolation_rejects_forged_dns_receipts_and_detour_bypass(self):
        defects = (
            "no-proxy-A", "wrong-proxy-name", "wrong-proxy-type",
            "no-upstream-dns-tunnel", "upstream-wrong-port",
            "upstream-public-host", "duplicate-app-tunnel",
            "selected-bypass", "direct-leaked-to-selected",
            "direct-leaked-to-proxy-dns", "proxy-to-node-dns",
            "proxy-to-direct-dns", "node-rejection", "tcp-responder-failed",
            "stale-before", "core-replaced", "LKG-drift",
        )
        for defect in defects:
            with self.subTest(defect=defect):
                outbound = fake.SyntheticDNS(dns.NODE_DOMAIN, 41002)
                direct_dns = fake.SyntheticDNS(dns.DIRECT_DOMAIN, 41003)
                tcp = fake.SyntheticDNS(proxy.PROXY_DOMAIN, 41004)
                node = fake.SyntheticNode()
                node.destination_receipts = []
                node.http_port, node.echo_port = 41004, 41001
                node.counter_lock = threading.Lock()
                initial = fake.running_status(
                    pid=333 if defect == "stale-before" else 222)
                ending = fake.running_status(
                    pid=333 if defect == "core-replaced" else 222,
                    lkg=9 if defect == "LKG-drift" else 7)
                def direct_control(port, _echo, _payload):
                    if port == 2080:
                        direct_dns.receipts.append(
                            (dns.DIRECT_DOMAIN, 1))
                        if defect == "direct-leaked-to-selected":
                            node.calls += 1
                        if defect == "direct-leaked-to-proxy-dns":
                            tcp.receipts.append(
                                (proxy.PROXY_DOMAIN, 1))
                def selected_client(_echo, _payload):
                    kind = (28 if defect == "no-proxy-A" else
                            15 if defect == "wrong-proxy-type" else 1)
                    name = (b"bad.invalid" if
                            defect == "wrong-proxy-name"
                            else proxy.PROXY_DOMAIN)
                    tcp.receipts.append((name, kind))
                    dest = [
                        (None, "127.0.0.1",
                         41001 if defect == "no-upstream-dns-tunnel"
                         else 41005 if defect == "upstream-wrong-port"
                         else 41004),
                        (proxy.PROXY_DOMAIN,
                         "1.1.1.1" if defect == "upstream-public-host"
                         else "127.0.0.1", 41001),
                    ]
                    if defect == "duplicate-app-tunnel":
                        dest.append((None, "127.0.0.1", 41001))
                    node.destination_receipts = dest
                    node.calls = (1 if defect == "selected-bypass"
                                  else len(dest))
                    if defect == "proxy-to-node-dns":
                        outbound.receipts.append((dns.NODE_DOMAIN, 1))
                    if defect == "proxy-to-direct-dns":
                        direct_dns.receipts.append(
                            (dns.DIRECT_DOMAIN, 1))
                    if defect == "node-rejection":
                        node.rejections = 1
                    if defect == "tcp-responder-failed":
                        tcp.failed = True
                with (mock.patch.object(
                        applied, "unix_json",
                        side_effect=[initial, ending]),
                      mock.patch.object(direct, "probe_direct_domain_socks",
                                        side_effect=direct_control),
                      mock.patch.object(applied,
                                        "probe_selected_socks_domain",
                                        side_effect=selected_client)):
                    with self.assertRaises(RuntimeError):
                        proxy.audit_managed_proxy_dns(
                            "/sock", 7, 222, 41001, node,
                            outbound, direct_dns, tcp)

    def test_workflow_retains_seven_native_airgaps_and_safe_diagnostics(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/core-provenance.yml").read_text()
        for marker in ("docker run --rm --pull never",
                       "--network none --cap-drop ALL",
                       "--user 10001:10001 --read-only"):
            self.assertEqual(workflow.count(marker), 7)
        self.assertIn("t24_airgap_managed_proxy_dns.py", workflow)
        self.assertEqual(proxy.SAFE_CODES[
            "Proxy DNS did not traverse exact Selected SOCKS upstream"],
            "proxy-dns-bypass")
        self.assertNotIn("user-password", proxy.SAFE_CODES)


if __name__ == "__main__":
    unittest.main()
