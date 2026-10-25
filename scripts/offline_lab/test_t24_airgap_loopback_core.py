#!/usr/bin/env python3
"""No network/VM/approved Core needed: fail-closed local SOCKS5 test harness."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

import t24_airgap_bootstrap as bootstrap
import t24_airgap_loopback_core as loopback


class LoopbackCorePolicyTests(unittest.TestCase):
    def make_config(self, root):
        def fake_checked(argv, env, timeout=15):
            if argv[1:3] == ["version", "-n"]:
                return "pinned-version\n"
            if argv[1:3] == ["check", "-c"]:
                return ""
            raise AssertionError("test tried an unapproved core operation")
        with mock.patch.object(bootstrap, "checked", side_effect=fake_checked):
            bootstrap.verify_core("/approved/core", "pinned-version", root, {})
        return root / "core-check.json"

    def test_inert_three_loopback_inbounds_can_be_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_config(Path(directory))
            loopback.require_inert_loopback_config(path)

    def test_remote_dns_tun_system_proxy_and_wrong_outbound_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_config(Path(directory))
            original = json.loads(path.read_text())
            mutations = (
                ("remote-controller", lambda doc: doc["experimental"]["clash_api"].update(
                    {"external_controller": "0.0.0.0:29090"})),
                ("tun-extra", lambda doc: doc.update({"tun": {}})),
                ("remote-dns", lambda doc: doc.update({"dns": {"servers": ["8.8.8.8"]}})),
                ("rule-set", lambda doc: doc["route"].update({"rule_set": ["geosite:cn"]})),
                ("inbound-wildcard", lambda doc: doc["inbounds"][0].update(
                    {"listen": "0.0.0.0"})),
                ("system-proxy", lambda doc: doc["inbounds"][0].update(
                    {"set_system_proxy": True})),
                ("remote-transport", lambda doc: doc["outbounds"][0].update(
                    {"type": "socks", "server": "8.8.8.8"})),
                ("remote-url", lambda doc: doc["experimental"].update(
                    {"external": "https://example.invalid"})),
            )
            for name, poison in mutations:
                with self.subTest(name=name):
                    doc = json.loads(json.dumps(original))
                    poison(doc)
                    path.write_text(json.dumps(doc))
                    with self.assertRaises(RuntimeError):
                        loopback.require_inert_loopback_config(path)

    def test_real_local_socketpair_socks5_connect_roundtrip(self):
        client, server = socket.socketpair()
        errors = []
        port = 34567
        payload = b"offline-28080"

        def fake_proxy():
            try:
                server.settimeout(2)
                self.assertEqual(loopback.exact_read(server, 3), b"\x05\x01\x00")
                server.sendall(b"\x05\x00")
                connect = loopback.exact_read(server, 10)
                self.assertEqual(connect[:8], b"\x05\x01\x00\x01\x7f\x00\x00\x01")
                self.assertEqual(struct.unpack("!H", connect[8:10])[0], port)
                server.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                               struct.pack("!H", port))
                self.assertEqual(loopback.exact_read(server, len(payload)), payload)
                server.sendall(loopback.REPLY_PREFIX + payload)
            except Exception as exc:
                errors.append(exc)
            finally:
                server.close()

        worker = threading.Thread(target=fake_proxy, daemon=True)
        worker.start()
        with mock.patch.object(loopback.socket, "create_connection",
                               return_value=client) as dial:
            loopback.connect_local_socks(28080, port, payload)
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors, errors)
        dial.assert_called_once_with(("127.0.0.1", 28080), timeout=3)

    def test_refuse_broken_socks5_handshake_and_nonlocal_port(self):
        client, server = socket.socketpair()
        def invalid_proxy():
            try:
                server.settimeout(2)
                loopback.exact_read(server, 3)
                server.sendall(b"\x05\x02")
            finally:
                server.close()
        worker = threading.Thread(target=invalid_proxy, daemon=True)
        worker.start()
        with mock.patch.object(loopback.socket, "create_connection",
                               return_value=client):
            with self.assertRaises(RuntimeError):
                loopback.connect_local_socks(28081, 30000, b"x")
        worker.join(timeout=3)
        with self.assertRaises(RuntimeError):
            loopback.connect_local_socks(9999, 30000, b"x")
        with self.assertRaises(RuntimeError):
            loopback.connect_local_socks(28081, 0, b"x")

    def test_core_api_must_deny_anonymous_then_check_authenticated_version(self):
        proper = json.dumps({
            "version": "sing-box pinned-version",
            "premium": True, "meta": True,
        }).encode()
        with mock.patch.object(loopback, "api_get_version",
                               side_effect=[(401, b""), (200, proper)]):
            loopback.check_local_core_api("pinned-version")
        for statuses in (
            [(200, b""), (200, proper)],
            [(401, b""), (403, proper)],
            [(401, b""), (200, b'{"premium":true,"meta":true}')],
            [(401, b""), (200, b'{"version":"sing-box pinned-version","premium":false,"meta":true}')],
        ):
            with self.subTest(statuses=statuses):
                with mock.patch.object(loopback, "api_get_version",
                                       side_effect=statuses):
                    with self.assertRaises((RuntimeError, ValueError)):
                        loopback.check_local_core_api("pinned-version")

    def test_workflow_requires_pinned_multiplatform_image_and_network_none(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/core-provenance.yml").read_text()
        self.assertIn("docker.io/library/python@sha256:", workflow)
        self.assertNotIn("python:3.12-slim-bookworm", workflow)
        self.assertIn("--network none --cap-drop ALL", workflow)
        self.assertIn("--user 10001:10001 --read-only", workflow)
        self.assertIn("t24_airgap_loopback_core.py", workflow)


if __name__ == "__main__":
    unittest.main()
