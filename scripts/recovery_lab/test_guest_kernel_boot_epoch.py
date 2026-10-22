#!/usr/bin/env python3
"""Synthetic T15/T23 guest kernel-epoch regression; no VM is ever restarted."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import unittest
from unittest import mock

import guest_kernel_boot_epoch as epoch
import guest_reboot_audit as guest
from test_guest_reboot_audit import GuestBootReadOnlyTests
import vm_postboot_observe as postboot
import vm_power_cut as vm

PRE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
POST = "ffffffff-1111-4222-8333-444444444444"


class KernelBootEpochTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("the guest evidence lab is non-root only")
        # Borrow only the original synthetic SQLite/setup fixture, without
        # re-running any of its tests or importing production user state.
        self.g = GuestBootReadOnlyTests(
            "test_subset_matches_but_cannot_certify_reboot_or_real_power_loss")
        self.g.setUp()
        self.addCleanup(self.g.doCleanups)
        baseline = guest.inspect(self.g.args)
        self.assertEqual(baseline["status"], "baseline_captured_no_reboot_claim")
        self.baseline = baseline["baseline_sha256"]
        self.args = argparse.Namespace(
            mode="capture", case=self.g.args.case, nonce=self.g.nonce,
            domain=self.g.args.domain, uuid=self.g.args.uuid,
            witness=str(self.g.witness), baseline_sha256=self.baseline,
            boot_epoch_sha256=None)
        self.epoch_file = self.g.witness / ("boot-epoch-" + self.g.nonce + ".json")
        self.g.args.mode = "verify"
        self.g.args.baseline_sha256 = self.baseline

    def inspect_with_boot(self, boot_id):
        with mock.patch.object(epoch, "read_kernel_boot_id", return_value=boot_id):
            return epoch.inspect(self.args)

    def capture(self):
        report = self.inspect_with_boot(PRE)
        self.assertEqual(
            report["status"], "guest_kernel_boot_identity_pinned_no_reboot_claim")
        self.assertFalse(report["kernel_boot_identity_changed_observed"])
        self.assertEqual(len(report["boot_epoch_sha256"]), 64)
        self.args.mode = "verify"
        self.args.boot_epoch_sha256 = report["boot_epoch_sha256"]
        return report

    def simulate_host_stop_then_operator_manual_start(self):
        machine = {"state": "running", "commands": []}
        def fake_virsh(command, domain):
            machine["commands"].append(command)
            if domain != self.g.args.domain:
                raise AssertionError("disposable VM identity mismatch")
            if command == "domuuid":
                return self.g.args.uuid
            if command == "domstate":
                return machine["state"]
            if command == "destroy":
                if machine["state"] != "running":
                    raise AssertionError("fake VM was already stopped")
                machine["state"] = "shut off"
                return ""
            raise AssertionError("unsafe libvirt operation")

        stop = argparse.Namespace(
            domain=self.g.args.domain, uuid=self.g.args.uuid,
            case=self.g.args.case, nonce=self.g.nonce,
            sandbox=str(self.g.witness), execute=True)
        stop_ack = "EXECUTE:" + ":".join((
            self.g.args.domain, self.g.args.uuid,
            self.g.args.case, self.g.nonce))
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK": stop_ack}):
            stopped = vm.run_case(
                stop, runner=fake_virsh, effective_uid=1000)
        self.assertEqual(stopped["status"], "virtual_guest_forced_off_observed")
        # Deliberate CI-only fake operator action, not a real VM start.
        machine["state"] = "running"
        observe = argparse.Namespace(
            domain=self.g.args.domain, uuid=self.g.args.uuid,
            case=self.g.args.case, nonce=self.g.nonce,
            sandbox=str(self.g.witness),
            baseline_sha256=self.baseline, record=True)
        ack = "OBSERVE:" + ":".join((
            self.g.args.domain, self.g.args.uuid, self.g.args.case,
            self.g.nonce, self.baseline))
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_POSTBOOT_ACK": ack}):
            seen = postboot.run_case(
                observe, runner=fake_virsh, effective_uid=1000)
        self.assertEqual(
            seen["status"], "virtual_guest_running_observed_after_forced_off")
        self.assertEqual(machine["commands"].count("destroy"), 1)
        self.assertNotIn("start", machine["commands"])

    def test_real_procfs_reader_is_canonical_on_linux(self):
        if sys.platform != "linux":
            self.skipTest("real /proc boot id only exists on Linux")
        self.assertRegex(epoch.read_kernel_boot_id(), vm.UUID_RE)

    def test_distinct_boot_id_can_be_observed_but_never_authorizes_restore(self):
        before_db = self.g.dbpath.read_bytes()
        self.capture()
        self.simulate_host_stop_then_operator_manual_start()
        report = self.inspect_with_boot(POST)
        self.assertEqual(
            report["status"], "guest_kernel_boot_identity_changed_manual_review_only")
        self.assertIs(report["kernel_boot_identity_changed_observed"], True)
        self.assertIs(report["host_running_observation_checked"], True)
        self.assertIs(report["sqlite_subset_checked"], False)
        for key in epoch.BOOT_FLAGS:
            self.assertIs(report[key], False, key)
        self.assertEqual(before_db, self.g.dbpath.read_bytes())
        self.assertNotIn(PRE.encode(), json.dumps(report).encode())
        self.assertNotIn(POST.encode(), json.dumps(report).encode())

    def test_same_linux_kernel_boot_id_fails_even_with_valid_fake_host_chain(self):
        self.capture()
        self.simulate_host_stop_then_operator_manual_start()
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(PRE)

    def test_missing_or_forged_external_boot_epoch_sha_fails_closed(self):
        self.capture()
        self.simulate_host_stop_then_operator_manual_start()
        self.args.boot_epoch_sha256 = "f" * 64
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(POST)
        self.args.boot_epoch_sha256 = hashlib.sha256(
            self.epoch_file.read_bytes()).hexdigest()
        forged = json.loads(self.epoch_file.read_text())
        forged["kernel_boot_id"] = POST
        self.epoch_file.write_text(json.dumps(forged))
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(POST)

    def test_missing_host_poststart_or_intent_forces_manual_hold(self):
        self.capture()
        self.simulate_host_stop_then_operator_manual_start()
        post = self.g.witness / ("poststart-" + self.g.nonce + ".json")
        post.unlink()
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(POST)

    def test_cannot_recapture_after_host_stop_or_reuse_nonce(self):
        self.capture()
        self.args.mode = "capture"
        with self.assertRaises(FileExistsError):
            self.inspect_with_boot(PRE)
        self.simulate_host_stop_then_operator_manual_start()
        self.epoch_file.unlink()
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(POST)

    def test_bad_boot_ids_and_unsafe_epoch_files_refused(self):
        bad = [
            "", "not-a-uuid", "A" * 36,
            "00000000-0000-0000-0000-000000000000",
            PRE + "\n", PRE + " extra",
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(guest.AuditRefusal):
                    self.inspect_with_boot(value)
                self.assertFalse(self.epoch_file.exists())
        self.capture()
        self.simulate_host_stop_then_operator_manual_start()
        epoch_file = self.epoch_file
        epoch_file.chmod(0o644)
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(POST)
        epoch_file.chmod(0o600)
        original = epoch_file.read_bytes()
        epoch_file.unlink()
        epoch_file.symlink_to(self.g.witness / ("baseline-" + self.g.nonce + ".json"))
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(POST)
        epoch_file.unlink()
        epoch_file.write_bytes(original)
        epoch_file.chmod(0o600)
        other = self.g.witness / "hardlinked.json"
        os.link(epoch_file, other)
        with self.assertRaises(guest.AuditRefusal):
            self.inspect_with_boot(POST)


if __name__ == "__main__":
    unittest.main()
