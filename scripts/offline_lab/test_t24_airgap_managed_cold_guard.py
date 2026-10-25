#!/usr/bin/env python3
"""Fast T24 configured-Core cold-start policy regressions, no Docker or Core."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

import t24_airgap_bootstrap as bootstrap
import t24_airgap_managed_cold_guard as cold


class ManagedColdGuardTests(unittest.TestCase):
    def status(self):
        return {
            "api_version": "v1", "core_configured": True,
            "core_desired_state": "stopped", "core_state": "stopped",
            "core_pid": 0, "core_circuit_open": False,
            "recovery_required": False, "config_revision": 0,
            "declaration_revision": 0,
        }

    def caps(self):
        flags = {key: False for key in bootstrap.DENIED}
        flags.update({
            "core_lifecycle_api": True, "managed_apply_runtime": True,
            "core_supervision": True, "unix_socket_api": True,
            "sqlite_state": True,
        })
        return {"api_version": "v1", "capabilities": flags}

    def test_configured_but_unapplied_cold_status(self):
        cold.configured_status(self.status())
        cold.configured_caps(self.caps())

    def test_cold_status_cannot_claim_core_is_running_or_generation_exists(self):
        mutations = (
            ("core_configured", False),
            ("core_desired_state", "running"),
            ("core_state", "running"),
            ("core_pid", 1234),
            ("applied_generation_id", 1),
            ("last_known_good_generation_id", 2),
            ("recovery_required", True),
            ("core_circuit_open", True),
            ("config_revision", 1),
            ("declaration_revision", 1),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                status = self.status()
                status[key] = value
                with self.assertRaises(RuntimeError):
                    cold.configured_status(status)

    def test_managed_capabilities_must_remain_guarded(self):
        for key in bootstrap.DENIED:
            with self.subTest(key=key):
                caps = self.caps()
                caps["capabilities"][key] = True
                with self.assertRaises(RuntimeError):
                    cold.configured_caps(caps)
        for key in ("core_lifecycle_api", "managed_apply_runtime",
                    "core_supervision", "sqlite_state"):
            with self.subTest(missing=key):
                caps = self.caps()
                caps["capabilities"][key] = False
                with self.assertRaises(RuntimeError):
                    cold.configured_caps(caps)

    def test_core_hash_binds_bytes_and_owner_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "core"
            source.write_bytes(b"synthetic-test-only-binary")
            source.chmod(0o500)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(
                cold.hash_pinned_core(source, digest, require_root_owner=False),
                digest)
            with self.assertRaises(RuntimeError):
                cold.hash_pinned_core(source, "f" * 64, require_root_owner=False)
            with self.assertRaises(RuntimeError):
                cold.hash_pinned_core(source, "not-sha", require_root_owner=False)
            alias = Path(directory) / "symlink"
            alias.symlink_to(source)
            with self.assertRaises(RuntimeError):
                cold.hash_pinned_core(alias, digest, require_root_owner=False)
            hardlink = Path(directory) / "other"
            os.link(source, hardlink)
            with self.assertRaises(RuntimeError):
                cold.hash_pinned_core(source, digest, require_root_owner=False)

    def test_core_hash_refuses_oversized_or_group_writable(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "core"
            source.write_bytes(b"small")
            source.chmod(0o522)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with self.assertRaises(RuntimeError):
                cold.hash_pinned_core(source, digest, require_root_owner=False)
            source.chmod(0o500)
            with mock.patch.object(cold, "MAX_CORE_BYTES", 4):
                with self.assertRaises(RuntimeError):
                    cold.hash_pinned_core(source, digest, require_root_owner=False)

    def test_private_secret_only_digest_persists(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state" / "karing-tui-v2"
            state.mkdir(parents=True)
            secret = state / "core-control.secret"
            secret.write_text("a" * 64, encoding="ascii")
            secret.chmod(0o600)
            want = hashlib.sha256(b"a" * 64).hexdigest()
            self.assertEqual(cold.private_secret(Path(directory)), want)
            self.assertNotEqual(want, "a" * 64)
            secret.chmod(0o644)
            with self.assertRaises(RuntimeError):
                cold.private_secret(Path(directory))

    def test_no_local_core_listener_may_exist_on_empty_generation(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with mock.patch.object(
                    cold, "CORE_PORTS", (listener.getsockname()[1],)):
                with self.assertRaises(RuntimeError):
                    cold.no_proxy_listener()

    def test_workflow_runs_three_independent_native_airgaps(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/core-provenance.yml").read_text()
        self.assertEqual(workflow.count("docker run --rm --pull never"), 3)
        self.assertEqual(workflow.count("--network none --cap-drop ALL"), 3)
        self.assertEqual(workflow.count("--user 10001:10001 --read-only"), 3)
        self.assertIn('sudo chown 0:0 "$stage/core"', workflow)
        self.assertIn("t24_airgap_managed_cold_guard.py", workflow)


if __name__ == "__main__":
    unittest.main()
