#!/usr/bin/env python3
"""Fast negative-policy tests for the T24 airgap startup probe (no Docker)."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import t24_airgap_bootstrap as probe


class AirgapPolicyTests(unittest.TestCase):
    def status(self):
        return {
            "api_version": "v1",
            "core_configured": False,
            "core_desired_state": "stopped",
            "core_state": "not-configured",
            "recovery_required": False,
            "config_revision": 0,
            "declaration_revision": 0,
        }

    def capabilities(self):
        values = {k: False for k in probe.DENIED}
        values.update({
            "sqlite_state": True,
            "unix_socket_api": True,
            "secure_runtime_paths": True,
        })
        return {"api_version": "v1", "capabilities": values}

    def test_valid_inert_status_and_capabilities(self):
        probe.verify_status(self.status())
        probe.verify_caps(self.capabilities())

    def test_active_core_recovery_or_applied_generation_is_not_offline(self):
        for key, value in (
            ("core_configured", True), ("core_desired_state", "running"),
            ("core_state", "running"), ("recovery_required", True),
            ("applied_generation_id", 42), ("core_pid", 100),
            ("config_revision", -1), ("api_version", "v2"),
        ):
            with self.subTest(key=key):
                status = self.status()
                status[key] = value
                with self.assertRaises(RuntimeError):
                    probe.verify_status(status)

    def test_distribution_capabilities_never_claim_success(self):
        for key in probe.DENIED:
            with self.subTest(key=key):
                value = self.capabilities()
                value["capabilities"][key] = True
                with self.assertRaises(RuntimeError):
                    probe.verify_caps(value)
        value = self.capabilities()
        value["capabilities"]["sqlite_state"] = False
        with self.assertRaises(RuntimeError):
            probe.verify_caps(value)

    def test_core_checker_uses_only_inert_local_config(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []

            def fake_run(argv, env, timeout=15):
                calls.append(list(argv))
                if argv[1:3] == ["version", "-n"]:
                    return "pinned-test-core\n"
                if argv[1:3] == ["check", "-c"]:
                    document = json.loads(Path(argv[3]).read_text())
                    self.assertEqual(len(document["inbounds"]), 3)
                    self.assertTrue(all(
                        inbound["listen"] == "127.0.0.1"
                        and inbound["set_system_proxy"] is False
                        for inbound in document["inbounds"]))
                    self.assertEqual(document["route"]["final"], "direct")
                    self.assertNotIn("tun", json.dumps(document).lower())
                    self.assertNotIn("rule_set", json.dumps(document).lower())
                    return ""
                raise AssertionError("core operation was not inert")

            with mock.patch.object(probe, "checked", side_effect=fake_run):
                probe.verify_core("/approved/core", "pinned-test-core",
                                  Path(directory), {})
            self.assertEqual(
                [command[1] for command in calls], ["version", "check"])

    def test_core_version_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "checked", return_value="wrong-core\n"):
                with self.assertRaises(RuntimeError):
                    probe.verify_core("/approved/core", "expected",
                                      Path(directory), {})


if __name__ == "__main__":
    unittest.main()
