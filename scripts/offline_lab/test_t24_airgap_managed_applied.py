#!/usr/bin/env python3
"""Fast fail-closed ADR 0149 policy tests; no Core/Docker/remote sockets."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

import t24_airgap_managed_applied as applied
import t24_airgap_loopback_core as loopback


class AppliedManagedPolicyTests(unittest.TestCase):
    def status(self, desired="stopped", running=False):
        return {
            "api_version": "v1", "core_configured": True,
            "core_desired_state": desired,
            "core_state": "running" if running else "stopped",
            "core_pid": 123 if running else 0,
            "core_circuit_open": False, "recovery_required": False,
            "config_revision": 1, "declaration_revision": 1,
            "applied_generation_id": 5,
        }

    def test_synthetic_v1_document_never_imports_cn_or_remote_endpoints(self):
        doc = applied.local_document(39871)
        applied.assert_synthetic_document(doc, 39871)
        serialized = json.dumps(doc, sort_keys=True)
        for forbidden in ("rule_sets", "region_append", "cn_preset",
                          "https://", "tun", "8.8.8.8", "example.com"):
            self.assertNotIn(forbidden, serialized)

    def test_mutated_declaration_must_fail_safe(self):
        source = applied.local_document(39871)
        modifications = (
            ("remote-node", lambda d: d["nodes"][0].update({"server": "8.8.8.8"})),
            ("public-node", lambda d: d["nodes"][0].update({"server": "0.0.0.0"})),
            ("selected-fallback", lambda d: d["selection"]["current"].update(
                {"default": {"kind": "direct"}})),
            ("foreign-port", lambda d: d["nodes"][0].update({"port": 4444})),
            ("rule-set", lambda d: d.update({"rule_sets": [
                {"ref": "geosite:cn", "sha256": "0" * 64, "format": "source"}]})),
            ("region", lambda d: d["routing"].update(
                {"region_append": {"region_code": "cn"}})),
            ("non-direct-final", lambda d: d["routing"].update(
                {"final": {"kind": "block"}})),
            ("remote-dns", lambda d: d["dns"]["profiles"][0].update(
                {"server": "1.1.1.1"})),
            ("tun", lambda d: d.update({"tun": True})),
        )
        for name, mutation in modifications:
            with self.subTest(name=name):
                altered = json.loads(json.dumps(source))
                mutation(altered)
                with self.assertRaises(RuntimeError):
                    applied.assert_synthetic_document(altered, 39871)

    def test_committed_status_must_bind_generation_and_run_intent(self):
        self.assertEqual(
            applied.committed_snapshot(self.status(), 5, "stopped", False), 0)
        self.assertEqual(
            applied.committed_snapshot(self.status("running", True), 5,
                                       "running", True), 123)
        changes = (
            ("config_revision", 2), ("declaration_revision", 2),
            ("applied_generation_id", None), ("last_known_good_generation_id", None),
            ("core_desired_state", "running"), ("core_state", "running"),
            ("core_pid", 999), ("recovery_required", True),
            ("core_circuit_open", True), ("core_configured", False),
        )
        for field, value in changes:
            with self.subTest(field=field):
                changed = self.status()
                changed[field] = value
                if field == "last_known_good_generation_id":
                    # An optional prior LKG ID is permitted and is not a
                    # replacement for the actual applied generation.
                    continue
                with self.assertRaises(RuntimeError):
                    applied.committed_snapshot(changed, 5, "stopped", False)

    def test_managed_proxy_port_and_payload_guards(self):
        for port in (0, 9999, 28080):
            with self.subTest(port=port):
                with self.assertRaises(RuntimeError):
                    applied.probe_port(port, 10000, b"x")
        with self.assertRaises(RuntimeError):
            applied.probe_port(2080, 10000, b"")

    def test_route_separation_requires_only_selected_to_dial_node(self):
        class Node:
            calls = 0
            failed = False

        def separated(port, echo_port, payload):
            self.assertEqual(echo_port, 40001)
            self.assertTrue(payload.endswith(str(port).encode()))
            if port == 2082:
                node.calls += 1

        node = Node()
        with mock.patch.object(applied, "probe_port", side_effect=separated):
            applied.probe_isolated_routes(40001, b"first-", node)
            applied.probe_isolated_routes(40001, b"restart-", node)
        self.assertEqual(node.calls, 2)

        def all_via_selected(port, echo_port, payload):
            node.calls += 1

        node = Node()
        with mock.patch.object(applied, "probe_port", side_effect=all_via_selected):
            with self.assertRaises(RuntimeError):
                applied.probe_isolated_routes(40001, b"bad-", node)

        node = Node()
        with mock.patch.object(applied, "probe_port", return_value=None):
            with self.assertRaises(RuntimeError):
                applied.probe_isolated_routes(40001, b"bypass-", node)

        def failed_node(port, echo_port, payload):
            if port == 2082:
                node.calls += 1
                node.failed = True

        node = Node()
        with mock.patch.object(applied, "probe_port", side_effect=failed_node):
            with self.assertRaises(RuntimeError):
                applied.probe_isolated_routes(40001, b"fail-", node)

    def test_node_rejects_nonlocal_connect_without_outbound_dial(self):
        with applied.LocalSocksServer(("127.0.0.1", 0), applied.LocalSocksNode) as srv:
            srv.echo_port = 40892
            srv.calls = 0
            srv.failed = False
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                with mock.patch.object(applied.socket, "create_connection",
                                       side_effect=AssertionError("external dial")):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)
                        sock.connect(srv.server_address)
                        sock.sendall(b"\x05\x01\x00")
                        self.assertEqual(applied.exact_read(sock, 2), b"\x05\x00")
                        sock.sendall(b"\x05\x01\x00\x01\x08\x08\x08\x08" +
                                     struct.pack("!H", 53))
                # Threaded request handler rejects before creating any outgoing socket.
                for _ in range(50):
                    if srv.failed:
                        break
                    threading.Event().wait(0.02)
                self.assertTrue(srv.failed)
                self.assertEqual(srv.calls, 0)
            finally:
                srv.shutdown()
                thread.join(timeout=3)

    def test_unix_http_api_is_strictly_local_and_bounded(self):
        with self.assertRaises(RuntimeError):
            applied.unix_json("/fake/sock", "POST",
                              "/v1/anything-else", {"x": 1})
        with self.assertRaises(RuntimeError):
            applied.unix_json("/fake/sock", "POST",
                              "/v1/declaration", {"oversized": "x" * 8192})

    def test_unix_client_is_closed_on_success_and_error(self):
        class DummyResponse:
            status = 200
            def read(self, _limit):
                return b'{"api_version":"v1"}'

        clients = []
        class DummyClient:
            def __init__(self, path, timeout):
                self.path = path
                self.timeout = timeout
                self.closed = False
                clients.append(self)
            def request(self, method, route, body=None, headers=None):
                self.method = method
                self.route = route
            def getresponse(self):
                return DummyResponse()
            def close(self):
                self.closed = True

        with mock.patch.object(applied, "UnixHTTP", DummyClient):
            doc = applied.unix_json("/test.sock", "GET", "/v1/status")
            self.assertEqual(doc["api_version"], "v1")
            self.assertTrue(clients[-1].closed)
            with self.assertRaises(RuntimeError):
                applied.unix_json("/test.sock", "GET", "/v1/status",
                                  expected=201)
            self.assertTrue(clients[-1].closed)

    def test_workflow_requires_four_separate_native_network_none_probes(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/core-provenance.yml").read_text()
        self.assertEqual(workflow.count("docker run --rm --pull never"), 4)
        self.assertEqual(workflow.count("--network none --cap-drop ALL"), 4)
        self.assertEqual(workflow.count("--user 10001:10001 --read-only"), 4)
        self.assertIn("t24_airgap_managed_applied.py", workflow)
        self.assertIn("--core-sha256 \"$expected_core_sha\"", workflow)
        self.assertIn("docker.io/library/python@sha256:", workflow)


if __name__ == "__main__":
    unittest.main()
