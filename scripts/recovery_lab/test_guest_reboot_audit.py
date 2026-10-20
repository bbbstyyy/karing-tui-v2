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
                    id INTEGER PRIMARY KEY,
                    base_revision INTEGER NOT NULL,
                    target_revision INTEGER NOT NULL,
                    config_json BLOB NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    manifest_json BLOB, manifest_sha256 TEXT,
                    source_map_json BLOB, source_map_sha256 TEXT,
                    created_at TEXT NOT NULL);
                CREATE TABLE daemon_state (
                    singleton INTEGER PRIMARY KEY,
                    config_revision INTEGER,
                    applied_generation_id INTEGER REFERENCES generations(id),
                    last_known_good_generation_id INTEGER REFERENCES generations(id),
                    recovery_required INTEGER,
                    core_desired_state TEXT, routing_mode TEXT, private_direct INTEGER);
                CREATE TABLE apply_journal(
                    id INTEGER PRIMARY KEY, generation_id INTEGER REFERENCES generations(id),
                    previous_generation_id INTEGER, base_revision INTEGER,
                    target_revision INTEGER, phase TEXT, active_slot INTEGER, error TEXT);
                CREATE TABLE apply_history(
                    id INTEGER PRIMARY KEY, generation_id INTEGER,
                    previous_generation_id INTEGER,
                    base_revision INTEGER NOT NULL DEFAULT 0,
                    target_revision INTEGER NOT NULL, phase TEXT NOT NULL,
                    config_sha256 TEXT NOT NULL, manifest_sha256 TEXT,
                    source_map_sha256 TEXT, error TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                    updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:01Z',
                    generation_created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                    archived_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:02Z');
                CREATE TABLE inert_restore_preparations(
                    id INTEGER PRIMARY KEY, candidate_scope TEXT NOT NULL,
                    archive_sha256 TEXT NOT NULL, inventory_sha256 TEXT NOT NULL,
                    archive_bytes INTEGER NOT NULL, baseline_json BLOB NOT NULL,
                    baseline_sha256 TEXT NOT NULL, phase TEXT NOT NULL,
                    active_slot INTEGER, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL);
                CREATE TABLE selection_state (
                    singleton INTEGER PRIMARY KEY, revision INTEGER, current_target_json BLOB);
            """)
            db.executemany("INSERT INTO schema_migrations VALUES(?)",
                           [(i,) for i in range(1, 19)])
            config = b'{"inbounds":[]}'
            db.execute(
                "INSERT INTO generations VALUES(1, 0, 1, ?, ?, NULL, NULL, NULL, NULL, ?)",
                (config, hashlib.sha256(config).hexdigest(), "2026-01-01T00:00:00Z"))
            db.execute("INSERT INTO daemon_state VALUES(1, 1, 1, 1, 0, 'running', 'rule', 0)")
            db.execute("INSERT INTO selection_state VALUES(1, 1, ?)", (b'{"kind":"auto"}',))
            db.execute(
                "INSERT INTO apply_history(id,generation_id,target_revision,phase,"
                "config_sha256,manifest_sha256,source_map_sha256)"
                " VALUES(1,1,1,'committed',?,NULL,NULL)",
                (hashlib.sha256(config).hexdigest(),))
        self.dbpath.chmod(0o600)


    def add_prepared(self):
        config = b'{"inbounds":[],"pending":true}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "INSERT INTO generations VALUES(2, 1, 2, ?, ?, NULL, NULL, NULL, NULL, ?)",
                (config, hashlib.sha256(config).hexdigest(), "2026-01-01T00:00:03Z"))
            db.execute("INSERT INTO apply_journal VALUES(2, 2, 1, 1, 2, 'prepared', 1, '')")


    @staticmethod
    def synthetic_inert_fence():
        config_sha = hashlib.sha256(b'{"inbounds":[]}').hexdigest()
        selected_sha = hashlib.sha256(b'{"kind":"auto"}').hexdigest()
        # Mirrors Go InertRestoreFence exported field declaration order.
        fence = {
            "ConfigRevision": 1,
            "AppliedGenerationID": 1,
            "LastKnownGoodGenerationID": 1,
            "DeclarationRevision": 1,
            "DeclarationSHA256": "a" * 64,
            "SelectionRevision": 1,
            "SelectionSHA256": selected_sha,
            "RoutingMode": "rule",
            "PrivateDirect": False,
            "CoreDesiredState": "running",
            "AppliedConfigSHA256": config_sha,
            "AppliedManifestSHA256": "b" * 64,
            "AppliedSourceMapSHA256": "c" * 64,
            "LastKnownGoodConfigSHA256": config_sha,
            "LastKnownGoodManifestSHA256": "b" * 64,
            "LastKnownGoodSourceMapSHA256": "c" * 64,
        }
        return json.dumps(fence, separators=(",", ":")).encode("utf-8")

    def add_inert_preparation(self, rid=1, phase="prepared"):
        fence = self.synthetic_inert_fence()
        active = 1 if phase == "prepared" else None
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "INSERT INTO inert_restore_preparations VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rid, ".ktui-restore-v1-ABC12345", "a" * 64, "b" * 64,
                 42000, fence, hashlib.sha256(fence).hexdigest(), phase,
                 active, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"))

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
        self.add_prepared()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE daemon_state SET recovery_required = 1")
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
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)


    def test_only_expected_prepared_to_interrupted_transition_is_read_only(self):
        self.add_prepared()
        self.capture()
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)  # ordinary verify cannot accept prepared
        original = self.dbpath.read_bytes()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_journal SET phase='interrupted', active_slot=NULL, "
                       "error='daemon restarted before apply completed' WHERE id=2")
        self.args.mode = "reconcile-verify"
        settled = self.dbpath.read_bytes()
        report = lab.inspect(self.args)
        self.assertEqual(report["status"], "prepared_journal_sqlite_subset_manual_review_only")
        self.assertTrue(report["prepared_journal_transition_checked"])
        self.assertFalse(report["guest_reboot_verified"])
        self.assertFalse(report["restore_authorized"])
        self.assertFalse(report["metadata_deletion_authorized"])
        self.assertEqual(settled, self.dbpath.read_bytes())
        self.assertNotEqual(original, settled)
        self.args.mode = "verify"
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_archived_baseline_digest_mismatch_refused_even_if_other_records_match(self):
        self.add_prepared()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_journal SET phase='interrupted', active_slot=NULL, "
                       "error='daemon restarted before apply completed' WHERE id=2")
        self.args.mode = "reconcile-verify"
        self.assertTrue(lab.inspect(self.args)["prepared_journal_transition_checked"])
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_history SET config_sha256=? WHERE id=1", ("0" * 64,))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_archived_baseline_missing_or_extra_history_refused(self):
        self.add_prepared()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_journal SET phase='interrupted', active_slot=NULL, "
                       "error='daemon restarted before apply completed' WHERE id=2")
        self.args.mode = "reconcile-verify"
        self.assertTrue(lab.inspect(self.args)["prepared_journal_transition_checked"])
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "INSERT INTO apply_history(id,generation_id,target_revision,phase,"
                "config_sha256,manifest_sha256,source_map_sha256)"
                " VALUES(3,1,1,'committed',?,NULL,NULL)",
                (hashlib.sha256(b'{"inbounds":[]}').hexdigest(),))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)


    def test_inert_fence_preflight_rejects_noncanonical_even_if_rehashed(self):
        original = self.synthetic_inert_fence()
        data = json.loads(original)
        modified = [
            b" " + original,
            json.dumps(dict(reversed(list(data.items()))),
                       separators=(",", ":")).encode("utf-8"),
            original[:-1] + b',"UnreviewedField":1}',
        ]
        for index, encoded in enumerate(modified):
            with self.subTest(index=index):
                with sqlite3.connect(self.dbpath) as db:
                    db.execute("DELETE FROM inert_restore_preparations")
                self.add_inert_preparation()
                with sqlite3.connect(self.dbpath) as db:
                    db.execute(
                        "UPDATE inert_restore_preparations "
                        "SET baseline_json=?, baseline_sha256=? WHERE id=1",
                        (encoded, hashlib.sha256(encoded).hexdigest()))
                self.args.mode = "capture"
                with self.assertRaises(lab.AuditRefusal):
                    lab.inspect(self.args)

    def test_inert_fence_preflight_refuses_go_invalid_values_with_matching_sha(self):
        original = json.loads(self.synthetic_inert_fence())
        for key, invalid in (
            ("ConfigRevision", 0),
            ("SelectionRevision", True),
            ("AppliedGenerationID", -1),
            ("CoreDesiredState", "activated"),
            ("PrivateDirect", 1),
            ("AppliedConfigSHA256", "not-a-hash"),
        ):
            with self.subTest(key=key):
                with sqlite3.connect(self.dbpath) as db:
                    db.execute("DELETE FROM inert_restore_preparations")
                self.add_inert_preparation()
                forged = dict(original)
                forged[key] = invalid
                encoded = json.dumps(forged, separators=(",", ":")).encode("utf-8")
                with sqlite3.connect(self.dbpath) as db:
                    db.execute(
                        "UPDATE inert_restore_preparations "
                        "SET baseline_json=?, baseline_sha256=? WHERE id=1",
                        (encoded, hashlib.sha256(encoded).hexdigest()))
                self.args.mode = "capture"
                with self.assertRaises(lab.AuditRefusal):
                    lab.inspect(self.args)

    def test_canonical_inert_fence_abandoned_record_remains_readonly(self):
        self.add_inert_preparation(phase="abandoned")
        before = self.dbpath.read_bytes()
        self.capture()
        report = lab.inspect(self.args)
        self.assertFalse(report["restore_authorized"])
        self.assertFalse(report["metadata_deletion_authorized"])
        self.assertEqual(before, self.dbpath.read_bytes())

    def test_pending_inert_restore_metadata_is_pinned_but_never_authorized(self):
        self.add_inert_preparation()
        old = self.dbpath.read_bytes()
        self.capture()
        result = lab.inspect(self.args)
        self.assertEqual(result["status"], "sqlite_subset_consistent_manual_review_only")
        for key in ("restore_authorized", "metadata_deletion_authorized",
                    "archive_hmac_verified", "guest_reboot_verified",
                    "physical_power_loss_verified"):
            self.assertFalse(result[key])
        self.assertEqual(old, self.dbpath.read_bytes())
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE inert_restore_preparations SET inventory_sha256=? WHERE id=1",
                       ("c" * 64,))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_rehashed_inert_fence_and_abandoned_phase_drift_are_refused(self):
        self.add_inert_preparation()
        self.capture()
        forged = json.loads(self.synthetic_inert_fence())
        forged["SelectionRevision"] = 2
        payload = json.dumps(forged, separators=(",", ":")).encode("utf-8")
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE inert_restore_preparations SET baseline_json=?, baseline_sha256=? WHERE id=1",
                (payload, hashlib.sha256(payload).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        with sqlite3.connect(self.dbpath) as db:
            original = self.synthetic_inert_fence()
            db.execute(
                "UPDATE inert_restore_preparations SET baseline_json=?, baseline_sha256=?, "
                "phase='abandoned', active_slot=NULL WHERE id=1",
                (original, hashlib.sha256(original).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_inert_journal_rejects_wrong_digest_unsafe_scope_and_timestamp(self):
        for field, invalid in (
            ("baseline_sha256", "e" * 64),
            ("candidate_scope", "../production-user-state"),
            ("updated_at", "not-a-timestamp"),
        ):
            with self.subTest(field=field):
                with sqlite3.connect(self.dbpath) as db:
                    db.execute("DELETE FROM inert_restore_preparations")
                self.add_inert_preparation()
                with sqlite3.connect(self.dbpath) as db:
                    db.execute(
                        "UPDATE inert_restore_preparations SET " + field + "=? WHERE id=1",
                        (invalid,))
                with self.assertRaises(lab.AuditRefusal):
                    lab.inspect(self.args)

    def test_inert_journal_refuses_more_than_32_records_even_when_abandoned(self):
        for rid in range(1, lab.MAX_INERT_RESTORE_ROWS + 2):
            self.add_inert_preparation(rid=rid, phase="abandoned")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def add_unreferenced_generation(self):
        # Retained confirmed history may keep a generation that is neither
        # Applied/LKG nor the newest pending journal candidate.
        payload = b'{"inbounds":[],"retained":"older"}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "INSERT INTO generations VALUES(8, 0, 1, ?, ?, NULL, NULL, NULL, NULL, ?)",
                (payload, hashlib.sha256(payload).hexdigest(),
                 "2026-01-01T00:00:04Z"))

    def test_retained_unreferenced_generation_content_change_fails_closed(self):
        self.add_unreferenced_generation()
        before = self.dbpath.read_bytes()
        self.capture()
        report = lab.inspect(self.args)
        self.assertEqual(report["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertFalse(report["archive_hmac_verified"])
        self.assertFalse(report["restore_authorized"])
        self.assertEqual(before, self.dbpath.read_bytes())
        # Rehash BOTH the old config and its stored digest; old Applied/LKG,
        # most recent apply candidate, history count and history SHA remain.
        forged = b'{"inbounds":[],"retained":"swapped_and_rehashed"}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE generations SET config_json=?, config_sha256=? WHERE id=8",
                (forged, hashlib.sha256(forged).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_retained_unreferenced_generation_timestamp_drift_fails_closed(self):
        self.add_unreferenced_generation()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE generations SET created_at=? WHERE id=8",
                ("2026-01-01T00:00:05Z",))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_retained_generation_malformed_digest_pair_and_nonjson_refused(self):
        self.add_unreferenced_generation()
        for sql, params in (
            ("UPDATE generations SET manifest_json=? WHERE id=8", (b"{}",)),
            ("UPDATE generations SET config_json=?, config_sha256=? WHERE id=8",
             (b"not-json", hashlib.sha256(b"not-json").hexdigest())),
            ("UPDATE generations SET created_at=? WHERE id=8", ("not-a-time",)),
        ):
            with sqlite3.connect(self.dbpath) as db:
                db.execute(
                    "UPDATE generations SET manifest_json=NULL, manifest_sha256=NULL,"
                    "config_json=?, config_sha256=?, created_at=? WHERE id=8",
                    (b'{"inbounds":[],"retained":"older"}',
                     hashlib.sha256(b'{"inbounds":[],"retained":"older"}').hexdigest(),
                     "2026-01-01T00:00:04Z"))
                db.execute(sql, params)
            with self.assertRaises(lab.AuditRefusal):
                lab.inspect(self.args)

    def test_retained_generation_count_over_128_refuses(self):
        payload = b'{"inbounds":[]}'
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO generations VALUES(?, 0, 1, ?, ?, NULL, NULL, NULL, NULL, ?)",
                ((gid, payload, hashlib.sha256(payload).hexdigest(),
                  "2026-01-01T00:00:04Z")
                 for gid in range(2, lab.MAX_GENERATION_ROWS + 2)))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_full_bounded_history_ledger_refuses_old_row_drift(self):
        with sqlite3.connect(self.dbpath) as db:
            digest = hashlib.sha256(b'{"inbounds":[]}').hexdigest()
            db.execute(
                "INSERT INTO apply_history(id,generation_id,target_revision,phase,"
                "config_sha256,manifest_sha256,source_map_sha256)"
                " VALUES(3,1,1,'committed',?,NULL,NULL)", (digest,))
        self.capture()
        original = self.dbpath.read_bytes()
        report = lab.inspect(self.args)
        self.assertEqual(report["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertEqual(original, self.dbpath.read_bytes())
        # Latest (id=3), row count and Applied/LKG remain unchanged.
        # Changing an older archived row must invalidate the pinned digest.
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_history SET error=? WHERE id=1",
                       ("modified historical error: never printed",))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_archive_ledger_refuses_unbounded_rows_and_long_error(self):
        digest = hashlib.sha256(b'{"inbounds":[]}').hexdigest()
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO apply_history(id,generation_id,target_revision,phase,"
                "config_sha256,manifest_sha256,source_map_sha256)"
                " VALUES(?,1,1,'committed',?,NULL,NULL)",
                ((i, digest) for i in range(2, lab.MAX_HISTORY_ROWS + 2)))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        with sqlite3.connect(self.dbpath) as db:
            db.execute("DELETE FROM apply_history WHERE id>1")
            db.execute("UPDATE apply_history SET error=? WHERE id=1",
                       ("s" * (lab.MAX_HISTORY_ERROR_BYTES + 1),))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_archived_ledger_malformed_old_record_refused(self):
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_history SET target_revision=3 WHERE id=1")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_reconciled_subset_refuses_candidate_drift_even_with_new_matching_digest(self):
        self.add_prepared()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_journal SET phase='interrupted', active_slot=NULL, "
                       "error='daemon restarted before apply completed' WHERE id=2")
        self.args.mode = "reconcile-verify"
        self.assertTrue(lab.inspect(self.args)["prepared_journal_transition_checked"])
        payload = b'{"inbounds":[],"replaced_candidate":true}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE generations SET config_json=?, config_sha256=? WHERE id=2",
                       (payload, hashlib.sha256(payload).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_forged_v2_baseline_with_noninteger_revision_refuses_cleanly(self):
        self.add_prepared()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_journal SET phase='interrupted', active_slot=NULL, "
                       "error='daemon restarted before apply completed' WHERE id=2")
        baseline = self.witness / ("baseline-" + self.nonce + ".json")
        forged = json.loads(baseline.read_text())
        forged["state"]["config_revision"] = None
        forged["state"]["latest_apply"]["base_revision"] = None
        baseline.write_text(json.dumps(forged), encoding="utf-8")
        self.args.baseline_sha256 = hashlib.sha256(baseline.read_bytes()).hexdigest()
        self.args.mode = "reconcile-verify"
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_reconciled_subset_refuses_other_phase_and_false_recovery_marker(self):
        self.add_prepared()
        self.capture()
        self.args.mode = "reconcile-verify"
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_journal SET phase='failed', active_slot=NULL WHERE id=2")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE apply_journal SET phase='interrupted', "
                       "error='incorrect reason' WHERE id=2")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)


if __name__ == "__main__":
    unittest.main()
