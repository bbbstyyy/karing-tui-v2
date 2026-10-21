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
        self.ready = self.witness / ("ready-" + self.nonce + ".txt")
        self.ready.write_bytes(lab.vm.marker_body(self.args.case, self.nonce))
        self.ready.chmod(0o600)
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
                    created_at TEXT NOT NULL,
                    restore_origin_generation_id INTEGER);
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
                CREATE TABLE declaration_revisions (
                    revision INTEGER PRIMARY KEY, parent_revision INTEGER,
                    document_json BLOB NOT NULL, document_sha256 TEXT NOT NULL,
                    source TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE declaration_state (
                    singleton INTEGER PRIMARY KEY, current_revision INTEGER);
                CREATE TABLE profile_snapshots (
                    id INTEGER PRIMARY KEY, profile_id TEXT NOT NULL,
                    source_kind TEXT NOT NULL, source_revision TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE profile_state (
                    profile_id TEXT PRIMARY KEY,
                    current_snapshot_id INTEGER NOT NULL REFERENCES profile_snapshots(id),
                    previous_snapshot_id INTEGER REFERENCES profile_snapshots(id),
                    updated_at TEXT NOT NULL);
                CREATE TABLE profile_snapshot_nodes (
                    snapshot_id INTEGER NOT NULL REFERENCES profile_snapshots(id),
                    ordinal INTEGER NOT NULL, node_id TEXT NOT NULL,
                    source_key TEXT NOT NULL, source_name TEXT NOT NULL,
                    payload_json BLOB NOT NULL, payload_sha256 TEXT NOT NULL,
                    PRIMARY KEY(snapshot_id, ordinal));
                CREATE TABLE profile_node_overlays (
                    profile_id TEXT NOT NULL, node_id TEXT NOT NULL,
                    revision INTEGER NOT NULL, disabled INTEGER NOT NULL,
                    favorite INTEGER NOT NULL, alias TEXT NOT NULL,
                    sort_rank INTEGER, updated_at TEXT NOT NULL,
                    PRIMARY KEY(profile_id, node_id));
                CREATE TABLE profile_sources (
                    profile_id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                    source_format TEXT NOT NULL, location_kind TEXT NOT NULL,
                    location TEXT NOT NULL, user_agent TEXT NOT NULL,
                    fetch_mode TEXT NOT NULL, fetch_profile_id TEXT NOT NULL,
                    fetch_node_id TEXT NOT NULL, filter_method TEXT NOT NULL,
                    filter_expression TEXT NOT NULL, filter_match_attribute INTEGER NOT NULL,
                    enabled INTEGER NOT NULL, update_interval_seconds INTEGER NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    last_attempt_at TEXT, last_success_at TEXT,
                    last_error TEXT NOT NULL, last_source_revision TEXT NOT NULL,
                    etag TEXT NOT NULL, last_modified TEXT NOT NULL,
                    subscription_upload_bytes INTEGER,
                    subscription_download_bytes INTEGER,
                    subscription_total_bytes INTEGER,
                    subscription_expires_at TEXT, subscription_usage_updated_at TEXT,
                    subscription_metadata_observed_at TEXT,
                    subscription_metadata_error TEXT NOT NULL,
                    consecutive_failures INTEGER NOT NULL, retry_after_at TEXT,
                    active_update_id TEXT, active_update_started_at TEXT);
                CREATE TABLE selection_state (
                    singleton INTEGER PRIMARY KEY, revision INTEGER, current_target_json BLOB);
            """)
            db.execute("INSERT INTO declaration_state VALUES(1, NULL)")
            db.executemany("INSERT INTO schema_migrations VALUES(?)",
                           [(i,) for i in range(1, 19)])
            config = b'{"inbounds":[]}'
            db.execute(
                "INSERT INTO generations VALUES(1, 0, 1, ?, ?, NULL, NULL, NULL, NULL, ?, NULL)",
                (config, hashlib.sha256(config).hexdigest(), "2026-01-01T00:00:00Z"))
            db.execute("INSERT INTO daemon_state VALUES(1, 1, 1, 1, 0, 'running', 'rule', 0)")
            db.execute("INSERT INTO selection_state VALUES(1, 1, ?)", (b'{"kind":"auto"}',))
            db.execute(
                "INSERT INTO apply_history(id,generation_id,target_revision,phase,"
                "config_sha256,manifest_sha256,source_map_sha256)"
                " VALUES(1,1,1,'committed',?,NULL,NULL)",
                (hashlib.sha256(config).hexdigest(),))
        self.dbpath.chmod(0o600)


    def add_profile_history(self):
        """Synthetic v18-shaped previous/current retained snapshot fixtures."""
        old = b'{"type":"http","server":"127.0.0.1","server_port":8080}'
        new = b'{"type":"http","server":"127.0.0.1","server_port":8081}'
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO profile_snapshots VALUES(?, ?, ?, ?, ?, ?)",
                [(1, "profile-a", "sing-box", "rev-1", "a" * 64,
                  "2026-01-01T00:00:00Z"),
                 (2, "profile-a", "sing-box", "rev-2", "b" * 64,
                  "2026-01-01T00:00:03Z")])
            db.execute("INSERT INTO profile_state VALUES(?, ?, ?, ?)",
                       ("profile-a", 2, 1, "2026-01-01T00:00:04Z"))
            db.executemany(
                "INSERT INTO profile_snapshot_nodes VALUES(?, ?, ?, ?, ?, ?, ?)",
                [(1, 0, "node-a", "tag-a", "Alpha", old,
                  hashlib.sha256(old).hexdigest()),
                 (2, 0, "node-a", "tag-a", "Alpha renamed", new,
                  hashlib.sha256(new).hexdigest())])

    @staticmethod
    def source_row(profile_id="profile-a", active=False):
        """Synthetic v18-shaped source without requiring a snapshot."""
        return {
            "profile_id": profile_id,
            "revision": 2,
            "source_format": "sing-box",
            "location_kind": "url",
            "location": "https://subscription.example.invalid/private?token=DO-NOT-PRINT",
            "user_agent": "karing-tui-v2/test",
            "fetch_mode": "direct",
            "fetch_profile_id": "",
            "fetch_node_id": "",
            "filter_method": "include",
            "filter_expression": "HK|Hong Kong",
            "filter_match_attribute": 1,
            "enabled": 1,
            "update_interval_seconds": 43200,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:01Z",
            "last_attempt_at": "2026-01-01T00:00:02Z",
            "last_success_at": "2026-01-01T00:00:03Z",
            "last_error": "temporary error",
            "last_source_revision": "etag-1",
            "etag": '"private-etag"',
            "last_modified": "Wed, 07 Oct 2026 16:00:00 GMT",
            "subscription_upload_bytes": 100,
            "subscription_download_bytes": 200,
            "subscription_total_bytes": 300,
            "subscription_expires_at": "2027-01-01T00:00:00Z",
            "subscription_usage_updated_at": "2026-01-01T00:00:03Z",
            "subscription_metadata_observed_at": "2026-01-01T00:00:03Z",
            "subscription_metadata_error": "",
            "consecutive_failures": 1,
            "retry_after_at": "2026-01-01T00:15:00Z",
            "active_update_id": "lease-test-1" if active else None,
            "active_update_started_at": "2026-01-01T00:00:04Z" if active else None,
        }

    def add_source(self, profile_id="profile-a", active=False):
        record = self.source_row(profile_id, active)
        fields = list(record)
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "INSERT INTO profile_sources(" + ", ".join(fields) + ")"
                " VALUES(" + ", ".join("?" for _ in fields) + ")",
                [record[field] for field in fields])

    def add_prepared(self):
        config = b'{"inbounds":[],"pending":true}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "INSERT INTO generations VALUES(2, 1, 2, ?, ?, NULL, NULL, NULL, NULL, ?, NULL)",
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
        # Host stop evidence is synthetic here; a fake JSON receipt does NOT
        # attest that a VM ever stopped or rebooted. We intentionally mirror
        # the actual vm_power_cut.py writer's exact immutable fields.
        common = {
            "schema_version": 1,
            "case": self.args.case, "nonce": self.args.nonce,
            "domain": self.args.domain, "domain_uuid": self.args.uuid,
            "marker_sha256": hashlib.sha256(self.ready.read_bytes()).hexdigest(),
            "guest_boot_verified": False,
            "physical_power_loss_verified": False,
            "post_reboot_consistency_verified": False,
            "restore_authorized": False,
            "metadata_deletion_authorized": False,
        }
        intent = self.witness / ("intent-" + self.nonce + ".json")
        intent.write_text(json.dumps({
            **common, "status": "intent_before_forced_virtual_stop",
            "time_utc": "2026-01-01T00:00:00+00:00",
        }), encoding="utf-8")
        intent.chmod(0o600)
        receipt = self.witness / ("observation-" + self.nonce + ".json")
        receipt.write_text(json.dumps({
            **common, "status": "virtual_guest_forced_off_observed",
            "time_utc": "2026-01-01T00:00:01+00:00",
        }), encoding="utf-8")
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

    def add_declaration_revisions(self):
        documents = (
            b'{"routing":{"mode":"rule"},"dns":{"enabled":true}}',
            b'{"routing":{"mode":"rule"},"dns":{"enabled":false}}',
        )
        with sqlite3.connect(self.dbpath) as db:
            for rev, document in enumerate(documents, start=1):
                db.execute(
                    "INSERT INTO declaration_revisions VALUES(?,?,?,?,?,?)",
                    (rev, None if rev == 1 else rev - 1, document,
                     hashlib.sha256(document).hexdigest(),
                     "test:t15-declaration", "2026-01-01T00:00:00Z"))
            db.execute("UPDATE declaration_state SET current_revision=2 WHERE singleton=1")

    def test_declaration_old_revision_rehashed_tamper_refuses(self):
        self.add_declaration_revisions()
        self.capture()
        old_bytes = self.dbpath.read_bytes()
        self.assertEqual(
            lab.inspect(self.args)["status"],
            "sqlite_subset_consistent_manual_review_only")
        self.assertEqual(old_bytes, self.dbpath.read_bytes())
        modified = b'{"routing":{"mode":"direct"},"dns":{"enabled":true}}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE declaration_revisions SET document_json=?,"
                "document_sha256=? WHERE revision=1",
                (modified, hashlib.sha256(modified).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_declaration_chain_and_current_pointer_refuse_bad_shapes(self):
        self.add_declaration_revisions()
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE declaration_revisions SET parent_revision=NULL WHERE revision=2")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE declaration_revisions SET parent_revision=1 WHERE revision=2")
            db.execute("UPDATE declaration_state SET current_revision=1 WHERE singleton=1")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_declaration_invalid_source_and_rehashed_nonjson_refused(self):
        self.add_declaration_revisions()
        bad = b'{"routing":NaN}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE declaration_revisions SET document_json=?, document_sha256=? "
                "WHERE revision=1", (bad, hashlib.sha256(bad).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        with sqlite3.connect(self.dbpath) as db:
            first = b'{"routing":{"mode":"rule"},"dns":{"enabled":true}}'
            db.execute(
                "UPDATE declaration_revisions SET document_json=?, document_sha256=?, "
                "source=? WHERE revision=1",
                (first, hashlib.sha256(first).hexdigest(), "invalid source with spaces"))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_declaration_history_more_than_128_rows_refused(self):
        document = b'{}'
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO declaration_revisions VALUES(?,?,?,?,?,?)",
                ((rev, None if rev == 1 else rev - 1, document,
                  hashlib.sha256(document).hexdigest(), "test:t15",
                  "2026-01-01T00:00:00Z")
                 for rev in range(1, lab.MAX_DECLARATION_ROWS + 2)))
            db.execute("UPDATE declaration_state SET current_revision=?",
                       (lab.MAX_DECLARATION_ROWS + 1,))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def add_unreferenced_generation(self):
        # Retained confirmed history may keep a generation that is neither
        # Applied/LKG nor the newest pending journal candidate.
        payload = b'{"inbounds":[],"retained":"older"}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "INSERT INTO generations VALUES(8, 0, 1, ?, ?, NULL, NULL, NULL, NULL, ?, NULL)",
                (payload, hashlib.sha256(payload).hexdigest(),
                 "2026-01-01T00:00:04Z"))

    def test_retained_restore_origin_reference_change_fails_closed(self):
        self.add_unreferenced_generation()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE generations SET restore_origin_generation_id=? WHERE id=8",
                (1,))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_invalid_retained_restore_origin_refuses_even_at_capture(self):
        self.add_unreferenced_generation()
        for bad in (-1, 0, "not-an-integer"):
            with self.subTest(bad=bad):
                with sqlite3.connect(self.dbpath) as db:
                    db.execute(
                        "UPDATE generations SET restore_origin_generation_id=? WHERE id=8",
                        (bad,))
                with self.assertRaises(lab.AuditRefusal):
                    lab.inspect(self.args)

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
                "INSERT INTO generations VALUES(?, 0, 1, ?, ?, NULL, NULL, NULL, NULL, ?, NULL)",
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

    def test_guest_v8_pins_old_profile_node_even_if_rehashed(self):
        self.add_profile_history()
        before = self.dbpath.read_bytes()
        self.capture()
        result = lab.inspect(self.args)
        self.assertEqual(result["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertFalse(result["restore_authorized"])
        self.assertEqual(before, self.dbpath.read_bytes())
        # Current profile pointer and its node remain identical. Recompute the
        # stored SHA on ONLY the previous retained snapshot node.
        replacement = b'{"type":"http","server":"127.0.0.1","server_port":9090}'
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE profile_snapshot_nodes SET payload_json=?, payload_sha256=? "
                "WHERE snapshot_id=1 AND ordinal=0",
                (replacement, hashlib.sha256(replacement).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v8_profile_pointer_and_name_drift_fail_closed(self):
        self.add_profile_history()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE profile_state SET previous_snapshot_id=NULL "
                       "WHERE profile_id='profile-a'")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        # Restore original pointer so only the historical source name changes.
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE profile_state SET previous_snapshot_id=1 "
                       "WHERE profile_id='profile-a'")
            db.execute("UPDATE profile_snapshot_nodes SET source_name='forged' "
                       "WHERE snapshot_id=1 AND ordinal=0")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v8_profile_invalid_hash_json_and_ordinal_refused(self):
        self.add_profile_history()
        cases = [
            ("UPDATE profile_snapshot_nodes SET payload_json=? WHERE snapshot_id=1",
             (b'{"type":"http","server_port":9000}',)),
            ("UPDATE profile_snapshot_nodes SET payload_json=?, payload_sha256=? "
             "WHERE snapshot_id=1",
             (b'{"number":NaN}', hashlib.sha256(b'{"number":NaN}').hexdigest())),
            ("UPDATE profile_snapshot_nodes SET ordinal=7 WHERE snapshot_id=1",
             ()),
            ("UPDATE profile_snapshots SET source_sha256='NOT-A-DIGEST' WHERE id=1",
             ()),
        ]
        for statement, params in cases:
            # Every case starts from the original fixture, not from a prior
            # invalid mutation.
            self.build_state_reset_profile_for_test()
            with sqlite3.connect(self.dbpath) as db:
                db.execute(statement, params)
            with self.assertRaises(lab.AuditRefusal):
                lab.inspect(self.args)

    def build_state_reset_profile_for_test(self):
        with sqlite3.connect(self.dbpath) as db:
            db.execute("DELETE FROM profile_snapshot_nodes")
            db.execute("DELETE FROM profile_state")
            db.execute("DELETE FROM profile_snapshots")
        self.add_profile_history()

    def test_guest_v8_profile_rows_and_payload_budget_refused(self):
        self.add_profile_history()
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO profile_snapshots VALUES(?, ?, ?, ?, ?, ?)",
                ((i, "profile-a", "sing-box", "", "a" * 64,
                  "2026-01-01T00:00:05Z")
                 for i in range(3, lab.MAX_PROFILE_SNAPSHOTS + 2)))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        self.build_state_reset_profile_for_test()
        huge = b" " * (lab.MAX_PROFILE_NODE_BYTES + 1)
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE profile_snapshot_nodes SET payload_json=?, "
                       "payload_sha256=? WHERE snapshot_id=1",
                       (huge, hashlib.sha256(huge).hexdigest()))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def add_dormant_overlays(self):
        """Persist an active overlay and one detached from current snapshots."""
        rows = [
            ("profile-a", "node-a", 2, 0, 1, "Visible current alias", 7,
             "2026-01-01T00:00:06Z"),
            ("profile-a", "node-retired", 4, 1, 0,
             "Private dormant alias - never print", 99,
             "2026-01-01T00:00:05Z"),
        ]
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO profile_node_overlays VALUES(?, ?, ?, ?, ?, ?, ?, ?)", rows)

    def reset_dormant_overlays(self):
        with sqlite3.connect(self.dbpath) as db:
            db.execute("DELETE FROM profile_node_overlays")
        self.add_dormant_overlays()

    def test_guest_v9_pins_detached_overlay_even_if_revision_unchanged(self):
        self.add_dormant_overlays()
        before = self.dbpath.read_bytes()
        self.capture()
        result = lab.inspect(self.args)
        self.assertEqual(result["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertFalse(result["restore_authorized"])
        self.assertEqual(before, self.dbpath.read_bytes())
        baseline = (self.witness / ("baseline-" + self.nonce + ".json")).read_bytes()
        self.assertNotIn(b"Private dormant alias", baseline)
        self.assertNotIn(b"node-retired", baseline)
        # Existing config, current source/node and overlay are unchanged.
        # Only old/dormant user intent changes without revision/CAS increment.
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE profile_node_overlays SET disabled=0, favorite=1, "
                "alias='tampered dormant preference' "
                "WHERE profile_id='profile-a' AND node_id='node-retired'")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v9_overlay_refuses_non_go_values_at_capture(self):
        self.add_dormant_overlays()
        mutations = [
            ("UPDATE profile_node_overlays SET revision=0 WHERE node_id='node-retired'", ()),
            ("UPDATE profile_node_overlays SET disabled=7 WHERE node_id='node-retired'", ()),
            ("UPDATE profile_node_overlays SET favorite=2 WHERE node_id='node-retired'", ()),
            ("UPDATE profile_node_overlays SET sort_rank=-1 WHERE node_id='node-retired'", ()),
            ("UPDATE profile_node_overlays SET sort_rank=? WHERE node_id='node-retired'",
             (lab.MAX_PROFILE_OVERLAY_SORT_RANK + 1,)),
            ("UPDATE profile_node_overlays SET alias=? WHERE node_id='node-retired'",
             (" " + "Alias",)),
            ("UPDATE profile_node_overlays SET alias=? WHERE node_id='node-retired'",
             ("A" * (lab.MAX_PROFILE_OVERLAY_ALIAS_BYTES + 1),)),
            ("UPDATE profile_node_overlays SET alias=? WHERE node_id='node-retired'",
             ("line\nbreak",)),
            ("UPDATE profile_node_overlays SET updated_at='not-a-time' "
             "WHERE node_id='node-retired'", ()),
        ]
        for statement, arguments in mutations:
            with self.subTest(statement=statement, arguments=str(arguments)[:40]):
                self.reset_dormant_overlays()
                with sqlite3.connect(self.dbpath) as db:
                    db.execute(statement, arguments)
                with self.assertRaises(lab.AuditRefusal):
                    lab.inspect(self.args)

    def test_guest_v9_overlay_budget_refuses_2049_rows(self):
        # A narrow guest cap, not the Go Store's 8192 PER-profile quota.
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO profile_node_overlays VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (("profile-a", f"former-node-{i:05d}", 1, 0, 0, "", None,
                  "2026-01-01T00:00:00Z")
                 for i in range(lab.MAX_PROFILE_OVERLAY_ROWS + 1)))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v9_reconcile_preserves_overlay_ledger(self):
        self.add_dormant_overlays()
        self.add_prepared()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE apply_journal SET phase='interrupted', active_slot=NULL, "
                "error='daemon restarted before apply completed' WHERE id=2")
        self.args.mode = "reconcile-verify"
        self.assertTrue(lab.inspect(self.args)["prepared_journal_transition_checked"])
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE profile_node_overlays SET sort_rank=NULL "
                "WHERE node_id='node-retired'")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v10_source_url_and_update_metadata_pinned_privately(self):
        # A source without any accepted snapshot is a legitimate Go state.
        self.add_source()
        before = self.dbpath.read_bytes()
        self.capture()
        result = lab.inspect(self.args)
        self.assertEqual(result["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertFalse(result["restore_authorized"])
        self.assertEqual(before, self.dbpath.read_bytes())
        baseline = (self.witness / ("baseline-" + self.nonce + ".json")).read_bytes()
        for private in (b"DO-NOT-PRINT", b"private-etag", b"HK|Hong Kong",
                        b"profile-a"):
            self.assertNotIn(private, baseline)
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE profile_sources SET location=? WHERE profile_id=?",
                       ("https://subscription.example.invalid/private?token=CHANGED",
                        "profile-a"))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v10_source_retry_and_subscription_counter_drift(self):
        self.add_source()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE profile_sources SET retry_after_at=?, consecutive_failures=? "
                "WHERE profile_id='profile-a'",
                ("2026-01-01T00:20:00Z", 2))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE profile_sources SET retry_after_at=?, consecutive_failures=? "
                "WHERE profile_id='profile-a'",
                ("2026-01-01T00:15:00Z", 1))
        self.assertEqual(lab.inspect(self.args)["status"],
                         "sqlite_subset_consistent_manual_review_only")
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE profile_sources SET subscription_total_bytes=900 "
                       "WHERE profile_id='profile-a'")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v10_pins_inflight_source_lease_without_claiming_recovery(self):
        self.add_source(active=True)
        self.capture()
        report = lab.inspect(self.args)
        self.assertEqual(report["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertFalse(report["guest_reboot_verified"])
        self.assertFalse(report["restore_authorized"])
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE profile_sources SET active_update_id=NULL, "
                "active_update_started_at=NULL, "
                "last_error='daemon restarted during profile update', "
                "consecutive_failures=consecutive_failures+1 "
                "WHERE profile_id='profile-a'")
        # Go's independent RecoverInterruptedProfileUpdates would write this
        # change; no general permission to absorb it from a T15 apply journal.
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v10_reconcile_refuses_profile_source_drift(self):
        self.add_source()
        self.add_prepared()
        self.capture()
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE apply_journal SET phase='interrupted', active_slot=NULL, "
                "error='daemon restarted before apply completed' WHERE id=2")
        self.args.mode = "reconcile-verify"
        self.assertTrue(lab.inspect(self.args)["prepared_journal_transition_checked"])
        with sqlite3.connect(self.dbpath) as db:
            db.execute(
                "UPDATE profile_sources SET filter_expression='different-region' "
                "WHERE profile_id='profile-a'")
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v10_invalid_source_shapes_refused_at_capture(self):
        self.add_source()
        cases = [
            ("source_format", "clash"),
            ("location", "file:///tmp/not-an-http-url"),
            ("location", "https://private:secret@subscription.invalid/list"),
            ("fetch_mode", "specific_node"),
            ("filter_method", "unknown"),
            ("filter_expression", " trailing "),
            ("filter_match_attribute", 2),
            ("enabled", -1),
            ("update_interval_seconds", 123),
            ("created_at", "broken"),
            ("last_success_at", "no-timezone"),
            ("last_error", "a" * 8193),
            ("subscription_metadata_error", "a" * 2049),
            ("subscription_total_bytes", -1),
            ("subscription_usage_updated_at", None),
            ("consecutive_failures", -1),
            ("active_update_started_at", "2026-01-01T00:00:04Z"),
            ("active_update_id", "lease with spaces"),
        ]
        for field, forged in cases:
            with self.subTest(field=field, forged=str(forged)[:20]):
                with sqlite3.connect(self.dbpath) as db:
                    db.execute("DELETE FROM profile_sources")
                self.add_source(active=field == "active_update_id")
                with sqlite3.connect(self.dbpath) as db:
                    db.execute("UPDATE profile_sources SET " + field + "=? "
                               "WHERE profile_id='profile-a'", (forged,))
                with self.assertRaises(lab.AuditRefusal):
                    lab.inspect(self.args)

    def test_guest_v10_profile_source_guest_row_cap(self):
        record = self.source_row("profile-0")
        fields = list(record)
        with sqlite3.connect(self.dbpath) as db:
            db.executemany(
                "INSERT INTO profile_sources(" + ", ".join(fields) + ") "
                "VALUES(" + ", ".join("?" for _ in fields) + ")",
                ([dict(record, profile_id=f"profile-{i}")[field]
                  for field in fields]
                 for i in range(lab.MAX_PROFILE_SOURCE_ROWS + 1)))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v11_missing_or_replaced_host_intent_is_not_a_stop_chain(self):
        self.capture()
        intent = self.witness / ("intent-" + self.nonce + ".json")
        intent.unlink()
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v11_rejects_marker_mutation_after_baseline_pin(self):
        self.capture()
        # Both host receipts still claim the original digest; no intent
        # or observation can upgrade a changed post-cut marker.
        self.ready.write_bytes(lab.vm.marker_body(
            "T15-checked-candidate", self.nonce))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v11_host_receipt_identity_digest_time_and_privacy(self):
        self.capture()
        intent = self.witness / ("intent-" + self.nonce + ".json")
        observed = self.witness / ("observation-" + self.nonce + ".json")
        pristine_intent = json.loads(intent.read_text())
        pristine_observed = json.loads(observed.read_text())
        cases = [
            (intent, "marker_sha256", "f" * 64),
            (intent, "domain_uuid", "f" * 8 + self.args.uuid[8:]),
            (intent, "guest_boot_verified", True),
            (intent, "restore_authorized", 0),
            (intent, "time_utc", "2026-01-01T00:00:00"),
            (intent, "time_utc", "not-a-clock"),
            (observed, "time_utc", "2025-12-31T23:59:59+00:00"),
            (observed, "post_reboot_consistency_verified", True),
            (observed, "status", "intent_before_forced_virtual_stop"),
            (observed, "unexpected_field", "silently forged"),
        ]
        for path, field, replacement in cases:
            with self.subTest(field=field, path=path.name):
                intent.write_text(json.dumps(pristine_intent))
                observed.write_text(json.dumps(pristine_observed))
                altered = dict(pristine_intent if path == intent else pristine_observed)
                altered[field] = replacement
                path.write_text(json.dumps(altered))
                with self.assertRaises(lab.AuditRefusal):
                    lab.inspect(self.args)

        intent.write_text(json.dumps(pristine_intent))
        observed.write_text(json.dumps(pristine_observed))
        intent.chmod(0o644)
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)
        intent.chmod(0o600)
        outside = self.witness / "second-link.json"
        os.link(observed, outside)
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)

    def test_guest_v11_mock_actual_host_producer_is_accepted_read_only(self):
        # Exercise the actual protected producer with an injected fake libvirt
        # runner, not a manually assembled JSON record and NEVER a real VM.
        before = self.dbpath.read_bytes()
        pinned = lab.inspect(self.args)
        self.assertEqual(pinned["status"], "baseline_captured_no_reboot_claim")
        state = {"machine": "running", "calls": []}

        def fake_session(command, domain):
            state["calls"].append((command, domain))
            if command == "domuuid":
                return self.args.uuid
            if command == "domstate":
                return state["machine"]
            if command == "destroy":
                if state["machine"] != "running":
                    raise AssertionError("fake destroyed an already stopped VM")
                state["machine"] = "shut off"
                return ""
            raise AssertionError("unexpected fake virsh operation")

        stop_args = argparse.Namespace(
            domain=self.args.domain, uuid=self.args.uuid,
            case=self.args.case, nonce=self.args.nonce,
            sandbox=str(self.witness), execute=True)
        with mock.patch.dict(os.environ, {"KTUI_LAB_VM_STOP_ACK":
                            "EXECUTE:" + ":".join(
                                (self.args.domain, self.args.uuid,
                                 self.args.case, self.args.nonce))}):
            result = lab.vm.run_case(
                stop_args, runner=fake_session, effective_uid=1000)
        self.assertEqual(result["status"], "virtual_guest_forced_off_observed")
        self.assertEqual(state["calls"].count(("destroy", self.args.domain)), 1)
        self.args.mode = "verify"
        self.args.baseline_sha256 = pinned["baseline_sha256"]
        verified = lab.inspect(self.args)
        self.assertEqual(verified["status"], "sqlite_subset_consistent_manual_review_only")
        self.assertTrue(verified["host_stop_chain_checked"])
        for key in ("guest_reboot_verified", "physical_power_loss_verified",
                    "restore_authorized", "metadata_deletion_authorized"):
            self.assertFalse(verified[key])
        self.assertEqual(before, self.dbpath.read_bytes())

    def test_guest_v11_duplicate_host_receipt_keys_fail_closed(self):
        self.capture()
        intent = self.witness / ("intent-" + self.nonce + ".json")
        raw = intent.read_bytes()
        self.assertIn(b'"status":', raw)
        # Even same-valued duplicate keys are ambiguous to other readers.
        intent.write_bytes(raw.replace(
            b'"status":', b'"status":"intent_before_forced_virtual_stop","status":', 1))
        with self.assertRaises(lab.AuditRefusal):
            lab.inspect(self.args)


if __name__ == "__main__":
    unittest.main()
