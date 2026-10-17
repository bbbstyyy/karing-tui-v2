#!/usr/bin/env python3
"""Safety unit tests: never contact libvirt or kill a real virtual machine."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import vm_power_cut as lab


class FakeSession:
    def __init__(self):
        self.state = "running"
        self.uuid = "01234567-89ab-cdef-0123-456789abcdef"
        self.commands = []

    def __call__(self, command, domain):
        self.commands.append((command, domain))
        if command == "domuuid":
            return self.uuid
        if command == "domstate":
            return self.state
        if command == "destroy":
            if self.state != "running":
                raise AssertionError("test double must not destroy a stopped VM")
            self.state = "shut off"
            return ""
        raise AssertionError("unapproved fake libvirt operation")


class PowerCutGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ktui-disposable-powercut-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.root.chmod(0o700)
        self.fake = FakeSession()
        self.args = argparse.Namespace(
            domain="ktui-t15t23-disposable-lab1",
            uuid=self.fake.uuid,
            case="T23-signed-reclaim-proof",
            nonce="a" * 32,
            sandbox=str(self.root),
            execute=False,
        )
        self.ready = self.root / ("ready-" + self.args.nonce + ".txt")
        self.ready.write_bytes(lab.marker_body(self.args.case, self.args.nonce))
        self.ready.chmod(0o600)

    def ack(self):
        return f"EXECUTE:{self.args.domain}:{self.args.uuid}:{self.args.case}:{self.args.nonce}"

    def run_apply(self, ack):
        self.args.execute = True
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK": ack}):
            return lab.run_case(self.args, runner=self.fake, effective_uid=1000)

    def test_preview_is_read_only_and_not_a_power_loss_attestation(self):
        report = lab.run_case(self.args, runner=self.fake)
        self.assertEqual(report["status"], "preview_only_no_vm_change")
        self.assertEqual(self.fake.state, "running")
        self.assertNotIn(("destroy", self.args.domain), self.fake.commands)
        self.assertFalse(report["physical_power_loss_verified"])
        self.assertFalse(report["post_reboot_consistency_verified"])
        self.assertFalse(report["restore_authorized"])
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [self.ready.name])

    def test_explicit_apply_records_two_private_witnesses_but_no_recovery_authority(self):
        report = self.run_apply(self.ack())
        self.assertEqual(report["status"], "virtual_guest_forced_off_observed")
        self.assertEqual(self.fake.state, "shut off")
        self.assertEqual(self.fake.commands.count(("destroy", self.args.domain)), 1)
        for filename, status in (
            ("intent-" + self.args.nonce + ".json", "intent_before_forced_virtual_stop"),
            ("observation-" + self.args.nonce + ".json", "virtual_guest_forced_off_observed"),
        ):
            path = self.root / filename
            st = path.stat()
            self.assertTrue(stat.S_ISREG(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
            self.assertEqual(st.st_nlink, 1)
            body = json.loads(path.read_text())
            self.assertEqual(body["status"], status)
            self.assertEqual(body["domain_uuid"], self.args.uuid)
            self.assertEqual(body["nonce"], self.args.nonce)
            self.assertFalse(body["physical_power_loss_verified"])
            self.assertFalse(body["guest_boot_verified"])
            self.assertFalse(body["post_reboot_consistency_verified"])
            self.assertFalse(body["restore_authorized"])
            self.assertFalse(body["metadata_deletion_authorized"])
        with self.assertRaises(lab.LabRefusal):
            self.run_apply(self.ack())  # no repeat/automatic replay

    def test_ack_must_exactly_bind_uuid_domain_case_and_nonce(self):
        self.args.execute = True
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK": "YES"}):
            with self.assertRaises(lab.LabRefusal):
                lab.run_case(self.args, runner=self.fake, effective_uid=1000)
        self.assertEqual(self.fake.commands, [])
        self.assertEqual(list(self.root.glob("intent-*.json")), [])

    def test_execute_refuses_privileged_host_user(self):
        self.args.execute = True
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK": self.ack()}):
            with self.assertRaises(lab.LabRefusal):
                lab.run_case(self.args, runner=self.fake, effective_uid=0)
        self.assertEqual(self.fake.commands, [])

    def test_unapproved_target_or_stale_vm_identity_is_refused(self):
        self.args.domain = "my-important-production-vm"
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.assertEqual(self.fake.commands, [])
        self.args.domain = "ktui-t15t23-disposable-lab1"
        self.args.uuid = "b" * 8 + self.args.uuid[8:]
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.assertEqual(self.fake.commands.count(("destroy", self.args.domain)), 0)

    def test_sandbox_and_marker_permissions_are_not_relaxed(self):
        self.root.chmod(0o755)
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.root.chmod(0o700)
        self.ready.chmod(0o644)
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.ready.chmod(0o600)
        self.ready.unlink()
        self.ready.symlink_to("/etc/passwd")
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.assertEqual(self.fake.commands, [])

    def test_wrong_case_nonce_and_hardlink_marker_are_refused(self):
        self.args.nonce = "A" * 32
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.args.nonce = "a" * 32
        self.ready.write_bytes(lab.marker_body("T15-prepared-journal", self.args.nonce))
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.ready.write_bytes(lab.marker_body(self.args.case, self.args.nonce))
        os.link(self.ready, self.root / "additional-hardlink")
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.assertEqual(self.fake.commands, [])

    def test_ambiguous_post_stop_observation_is_not_silent_success_or_retry(self):
        self.args.execute = True
        base_runner = self.fake

        def unreliable(command, domain):
            if command == "domstate" and ("destroy", domain) in base_runner.commands:
                return "unknown"
            return base_runner(command, domain)

        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK": self.ack()}):
            with self.assertRaises(lab.LabRefusal):
                lab.run_case(self.args, runner=unreliable, effective_uid=1000)
        self.assertEqual(self.fake.commands.count(("destroy", self.args.domain)), 1)
        self.assertTrue((self.root / ("intent-" + self.args.nonce + ".json")).exists())
        self.assertFalse((self.root / ("observation-" + self.args.nonce + ".json")).exists())
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK": self.ack()}):
            with self.assertRaises(lab.LabRefusal):
                lab.run_case(self.args, runner=unreliable, effective_uid=1000)
        self.assertEqual(self.fake.commands.count(("destroy", self.args.domain)), 1)

    def test_vm_must_be_running_and_nonce_must_be_unique(self):
        self.fake.state = "shut off"
        with self.assertRaises(lab.LabRefusal):
            lab.run_case(self.args, runner=self.fake)
        self.assertEqual(self.fake.commands.count(("destroy", self.args.domain)), 0)
        self.assertEqual(list(self.root.glob("intent-*.json")), [])


if __name__ == "__main__":
    unittest.main()
