#!/usr/bin/env python3
"""Non-destructive post-VM-stop safety tests: fake libvirt ONLY."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import vm_power_cut as vm
import vm_postboot_observe as postboot


class FakeUserSession:
    def __init__(self):
        self.uuid = "01234567-89ab-cdef-0123-456789abcdef"
        self.state = "running"
        self.calls = []

    def __call__(self, command, domain):
        self.calls.append((command, domain))
        if command == "domuuid":
            return self.uuid
        if command == "domstate":
            return self.state
        if command == "destroy":
            if self.state != "running":
                raise AssertionError("fake destroy cannot repeat")
            self.state = "shut off"
            return ""
        raise AssertionError("an unsafe libvirt operation was requested")


class HostPoststartGuardTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("host lab requires an ordinary non-root test user")
        self.temp = tempfile.TemporaryDirectory(prefix="ktui-test-poststart-")
        self.addCleanup(self.temp.cleanup)
        self.env = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.temp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.fake = FakeUserSession()
        self.nonce = "a" * 32
        self.domain = "ktui-t15t23-disposable-poststart"
        self.case = "T15-prepared-journal"
        self.witness = (Path(self.temp.name) / "karing-tui-v2" / "recovery-lab" /
                        ("ktui-powercut-disposable-" + self.nonce))
        self.witness.mkdir(mode=0o700, parents=True)
        self.witness.chmod(0o700)
        self.marker = self.witness / ("ready-" + self.nonce + ".txt")
        self.marker.write_bytes(vm.marker_body(self.case, self.nonce))
        self.marker.chmod(0o600)
        self.baseline = self.witness / ("baseline-" + self.nonce + ".json")
        self.baseline.write_bytes((json.dumps({
            "format": postboot.BASELINE_VERSION, "case": self.case,
            "nonce": self.nonce, "domain": self.domain,
            "domain_uuid": self.fake.uuid,
            "phase_marker_sha256": hashlib.sha256(self.marker.read_bytes()).hexdigest(),
            "state": {"only": "private throwaway test data"},
        }, sort_keys=True) + "\n").encode("utf-8"))
        self.baseline.chmod(0o600)
        self.baseline_sha = hashlib.sha256(self.baseline.read_bytes()).hexdigest()
        self.args = argparse.Namespace(
            domain=self.domain, uuid=self.fake.uuid, case=self.case,
            nonce=self.nonce, sandbox=str(self.witness),
            baseline_sha256=self.baseline_sha, record=False,
        )
        self.host_stop()
        # An operator would now manually restart the disposable VM.
        self.fake.state = "running"

    def host_stop(self):
        stop = argparse.Namespace(
            domain=self.domain, uuid=self.fake.uuid, case=self.case,
            nonce=self.nonce, sandbox=str(self.witness), execute=True)
        ack = f"EXECUTE:{self.domain}:{self.fake.uuid}:{self.case}:{self.nonce}"
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK": ack}):
            vm.run_case(stop, runner=self.fake, effective_uid=1000)

    def post_ack(self):
        return (f"OBSERVE:{self.domain}:{self.fake.uuid}:{self.case}:"
                f"{self.nonce}:{self.baseline_sha}")

    def run_record(self, ack=None):
        self.args.record = True
        with mock.patch.dict(
                os.environ, {"KTUI_LAB_VM_POSTBOOT_ACK":
                             self.post_ack() if ack is None else ack}):
            return postboot.run_case(
                self.args, runner=self.fake, effective_uid=1000)

    def test_preview_never_writes_and_never_changes_vm_state(self):
        before = list(self.witness.iterdir())
        previous_calls = list(self.fake.calls)
        report = postboot.run_case(self.args, runner=self.fake)
        self.assertEqual(report["status"], "preview_only_no_receipt")
        self.assertEqual(set(before), set(self.witness.iterdir()))
        self.assertEqual(self.fake.state, "running")
        self.assertTrue(report["guest_boot_verified"] is False)
        self.assertFalse(report["restore_authorized"])
        self.assertFalse(report["physical_power_loss_verified"])
        new = self.fake.calls[len(previous_calls):]
        self.assertEqual(new, [
            ("domuuid", self.domain), ("domstate", self.domain)])

    def test_exact_approved_record_durable_and_nonauthorizing(self):
        before_destroy = self.fake.calls.count(("destroy", self.domain))
        report = self.run_record()
        self.assertEqual(report["status"], "virtual_guest_running_observed_after_forced_off")
        path = self.witness / ("poststart-" + self.nonce + ".json")
        self.assertTrue(path.exists())
        info = path.stat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(json.loads(path.read_text()), report)
        self.assertEqual(report["baseline_sha256"], self.baseline_sha)
        for key in ("guest_boot_verified", "post_reboot_consistency_verified",
                    "physical_power_loss_verified", "core_health_verified",
                    "archive_hmac_verified", "restore_authorized",
                    "metadata_deletion_authorized"):
            self.assertIs(report[key], False)
        self.assertEqual(self.fake.calls.count(("destroy", self.domain)),
                         before_destroy)
        with self.assertRaises(vm.LabRefusal):
            self.run_record()  # original receipt is immutable/one shot
        self.assertEqual(self.fake.calls.count(("destroy", self.domain)),
                         before_destroy)

    def test_missing_ack_or_root_record_refused_before_libvirt(self):
        self.args.record = True
        existing = list(self.fake.calls)
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_POSTBOOT_ACK": "YES"}):
            with self.assertRaises(vm.LabRefusal):
                postboot.run_case(self.args, runner=self.fake, effective_uid=1000)
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_POSTBOOT_ACK": self.post_ack()}):
            with self.assertRaises(vm.LabRefusal):
                postboot.run_case(self.args, runner=self.fake, effective_uid=0)
        self.assertEqual(self.fake.calls, existing)

    def test_guest_not_running_or_wrong_uuid_fails_without_receipt(self):
        self.fake.state = "shut off"
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        self.fake.state = "running"
        self.fake.uuid = "f" * 8 + self.fake.uuid[8:]
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        self.assertFalse((self.witness / ("poststart-" + self.nonce + ".json")).exists())

    def test_changed_baseline_sha_or_marker_fails_before_libvirt(self):
        old = list(self.fake.calls)
        self.args.baseline_sha256 = "f" * 64
        with self.assertRaises(vm.LabRefusal):
            self.run_record(ack=self.post_ack())
        self.args.baseline_sha256 = self.baseline_sha
        self.marker.write_bytes(vm.marker_body("T15-checked-candidate", self.nonce))
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        self.assertEqual(old, self.fake.calls)

    def test_missing_or_forged_intent_and_observation_are_rejected(self):
        intent = self.witness / ("intent-" + self.nonce + ".json")
        original = intent.read_bytes()
        intent.unlink()
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        intent.write_bytes(original)
        intent.chmod(0o600)
        record = json.loads(intent.read_text())
        record["status"] = "virtual_guest_forced_off_observed"
        intent.write_text(json.dumps(record))
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        intent.write_bytes(original)
        receipt = self.witness / ("observation-" + self.nonce + ".json")
        observed = json.loads(receipt.read_text())
        observed["time_utc"] = "9999-12-31T23:59:59+00:00"
        receipt.write_text(json.dumps(observed))
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        self.assertFalse((self.witness / ("poststart-" + self.nonce + ".json")).exists())

    def test_symlink_hardlink_public_permission_and_duplicate_fields_refused(self):
        stop_receipt = self.witness / ("observation-" + self.nonce + ".json")
        original = stop_receipt.read_bytes()
        stop_receipt.chmod(0o644)
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        stop_receipt.chmod(0o600)
        extra = self.witness / "hardlink.json"
        os.link(stop_receipt, extra)
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        extra.unlink()
        stop_receipt.unlink()
        stop_receipt.symlink_to(self.baseline)
        with self.assertRaises(vm.LabRefusal):
            self.run_record()
        stop_receipt.unlink()
        stop_receipt.write_bytes(original)
        stop_receipt.chmod(0o600)
        stop_receipt.write_bytes(original.replace(
            b'"status":', b'"status":"virtual_guest_forced_off_observed","status":', 1))
        with self.assertRaises(vm.LabRefusal):
            self.run_record()


if __name__ == "__main__":
    unittest.main()
