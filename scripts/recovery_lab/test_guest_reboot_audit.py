#!/usr/bin/env python3
"""Mock guest filesystem regression; never reboot or touch a real VM."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

import guest_reboot_audit as lab


class GuestBootReadOnlyTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("test uses the same ordinary-user identity as the real guest")
        self.temp = tempfile.TemporaryDirectory(prefix="ktui-guest-readonly-")
        self.addCleanup(self.temp.cleanup)
        self.env = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.temp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.nonce = "f" * 32
        self.app = Path(self.temp.name) / "karing-tui-v2"
        self.app.mkdir(mode=0o700)
        (self.app / "recovery-lab").mkdir(mode=0o700)
        self.witness = self.app / "recovery-lab" / ("ktui-powercut-disposable-" + self.nonce)
        self.witness.mkdir(mode=0o700)
        self.dbpath = self.app / "state.db"
        self.build_state()
        self.args = argparse.Namespace(
            mode="capture", case="T15-prepared-journal", nonce=self.nonce,
            domain="ktui-t15t23-disposable-g1",
            uuid="01234567-89ab-cdef-0123-456789abcdef",
            witness=str(self.witness), baseline_sha256=None,
        )
        os.environ["KTUI_LAB_GUEST_AUDIT_ACK"] = self.ack()
        self.addCleanup(lambda: os.environ.pop("KTUI_LAB_GUEST_AUDIT_ACK", None))

    def build_state(self):
        with sqlite3.connect(self.dbpath) as db:
            db.executescript("""
                CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY);
                CREATE TABLE generations (
                    id INTEGER PRIMARY KEY, config_json BLOB NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    manifest_json BLOB, manifest_sha256 TEXT,
                    source_map_json BLOB, source_map_sha256 TEXT);
                CREATE TABLE daemon_state (
                    singleton INTEGER PRIMARY KEY,
                    config_revision INTEGER,
                    applied_generation_id INTEGER REFERENCES generations(id),
                    last_known_good_generation_id INTEGER REFERENCES generations(id),
                    recovery_required INTEGER,
                    core_desired_state TEXT, routing_mode TEXT, private_direct INTEGER);
                CREATE TABLE apply_journal(id INTEGER PRIMARY KEY, phase TEXT, active_slot INTEGER);
                CREATE TABLE inert_restore_preparations(id INTEGER PRIMARY KEY, phase TEXT);
                CREATE TABLE selection_state (
                    singleton INTEGER PRIMARY KEY, revision INTEGER, current_target_json BLOB);
            """)
            db.executemany("INSERT INTO schema_migrations VALUES(?)",
                           [(i,) for i in range(1, 19)])
            config = b'{"inbounds":[]}'
            db.execute("INSERT INTO generations VALUES(1, ?, ?, NULL, NULL, NULL, NULL)",
                       (config, hashlib.sha256(config).hexdigest()))
            db.execute("INSERT INTO daemon_state VALUES(1, 1, 1, 1, 0, 'running', 'rule', 0)")
            db.execute("INSERT INTO selection_state VALUES(1, 1, ?)", (b'{"kind":"auto"}',))
        self.dbpath.chmod(0o600)

    def ack(self):
        return "GUEST_AUDIT:" + ":".join((
            self.args.domain, self.args.uuid, self.args.case, self.args.nonce))

    def capture(self):
        record = lab.inspect(self.args)
        self.assertEqual(record["status"], "baseline_captured_no_reboot_claim")
        self.assertFalse(record["physical_power_loss_verified"])
        self.args.mode = "verify"
        self.args.baseline_sha256 = record["baseline_sha256"]
        observed = {
            "schema_version": 1,
            "status": "virtual_guest_forced_off_observed",
            "case": self.args.case, "nonce": self.args.nonce,
            "domain": self.args.domain, "domain_uuid": self.args.uuid,
            "physical_power_loss_verified": False,
            "post_reboot_consistency_verified": False,
            "restore_authorized": False,
            "metadata_deletion_authorized": False,
        }
        receipt = self.witness / ("observation-" + self.nonce + ".json")
        receipt.write_text(json.dumps(observed), encoding="utf-8")
        receipt.chmod(0o600)
        return receipt

    def test_subset_matches_but_cannot_certify_reboot_or_real_power_loss(self):
        original = self.dbpath.read_bytes()
        self.capture()
        result = lab.inspect(self.args)
        self.assertEqual(result["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertTrue(result["sqlite_subset_checked"])
        for field in ("guest_reboot_verified", "physical_power_loss_verified",
                      "core_health_verified", "archive_hmac_verified",
                      "restore_authorized", "metadata_deletion_authorized"):
            self.assertFalse(result[field], field)
        self.assertEqual(original, self.dbpath.read_bytes())
        self.assertEqual(stat.S_IMODE((self.witness / ("baseline-" + self.nonce + ".json")).stat().st_mode), 0o600)

    def test_changed_selection_or_generation_digest_fails_closed(self):
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE selection_state SET revision = 2")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE selection_state SET revision = 1")
            db.execute("UPDATE generations SET config_json = ?", (b'{"tampered":true}',))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_corrupt_witness_and_identity_binding_refused(self):
        receipt = self.capture()
        self.args.baseline_sha256 = "a" * 64
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        self.args.baseline_sha256 = hashlib.sha256(
            (self.witness / ("baseline-" + self.nonce + ".json")).read_bytes()).hexdigest()
        receipt_obj = json.loads(receipt.read_text())
        receipt_obj["physical_power_loss_verified"] = True
        receipt.write_text(json.dumps(receipt_obj))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        receipt_obj["physical_power_loss_verified"] = False
        receipt_obj["domain_uuid"] = "f" * 8 + receipt_obj["domain_uuid"][8:]
        receipt.write_text(json.dumps(receipt_obj))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_unreconciled_apply_requires_manual_hold(self):
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE daemon_state SET recovery_required = 1")
            db.execute("INSERT INTO apply_journal VALUES(1,'prepared',1)")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_schema_foreign_key_and_unsafe_private_path_rejected(self):
        self.args.mode = "capture"
        self.dbpath.chmod(0o644)
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        self.dbpath.chmod(0o600)
        with sqlite3.connect(self.dbpath) as db:
            db.execute("DELETE FROM schema_migrations WHERE version=18")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_no_existing_baseline_is_overwritten(self):
        self.capture()
        self.args.mode = "capture"
        with self.assertRaises(FileExistsError):
            lab.inspect(self.args)

    def test_symlinked_witness_is_refused(self):
        self.capture()
        baseline = self.witness / ("baseline-" + self.nonce + ".json")
        outside = self.witness / "elsewhere.txt"
        outside.write_bytes(baseline.read_bytes())
        outside.chmod(0o600)
        baseline.unlink()
        baseline.symlink_to(outside)
        with self.assertRaises(OSError):
            lab.inspect(self.args)


if __name__ == "__main__":
    unittest.main()
