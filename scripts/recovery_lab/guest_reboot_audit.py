#!/usr/bin/env python3
"""Read-only, disposable-guest SQLite replay preflight for T15/T23.

NEVER claims power-loss replay, Core health, or restore/delete authority.  This
tool assumes a separate guest test fixture and a user-session VM stop witness;
it neither boots a VM nor opens a write connection to the live SQLite state.
"""
from __future__ import annotations

import argparse
from contextlib import closing, ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import quote

import vm_power_cut as vm

SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_DB = 64 << 20  # deliberately narrower than the application's 768 MiB archive bound
MAX_WITNESS = 16 << 10
VERSION = 1


class AuditRefusal(Exception):
    pass


def refuse(message: str):
    raise AuditRefusal(message)


def private_fd(path: Path, maximum: int, directory: bool = False) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
            refuse("private path-to-inode identity changed")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in (
                (0o700,) if directory else (0o400, 0o600)):
            refuse("state or witness permissions are not private")
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                refuse("witness directory is not a directory")
        elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
              info.st_size <= 0 or info.st_size > maximum):
            refuse("witness or SQLite file is not a bounded private regular file")
        return fd
    except BaseException:
        if "fd" in locals():
            os.close(fd)
        raise


def file_identity(fd: int, path: Path):
    a = os.fstat(fd)
    b = os.stat(path, follow_symlinks=False)
    return (a.st_dev, a.st_ino, a.st_size, a.st_mode, a.st_mtime_ns,
            a.st_ctime_ns) == (
                b.st_dev, b.st_ino, b.st_size, b.st_mode, b.st_mtime_ns,
                b.st_ctime_ns)


def private_json(path: Path, maximum=MAX_WITNESS) -> tuple[dict, str]:
    fd = private_fd(path, maximum)
    try:
        info = os.fstat(fd)
        raw = os.pread(fd, maximum + 1, 0)
        if len(raw) != info.st_size or not file_identity(fd, path):
            refuse("witness changed while being read")
        doc = json.loads(raw)
        if not isinstance(doc, dict):
            refuse("witness must be a JSON object")
        return doc, hashlib.sha256(raw).hexdigest()
    except (ValueError, UnicodeError, OSError) as exc:
        raise AuditRefusal("invalid private witness") from exc
    finally:
        os.close(fd)


def sha_blob(raw, expected) -> str:
    if not isinstance(raw, bytes) or not isinstance(expected, str) or not SHA.fullmatch(expected):
        refuse("missing or noncanonical generation digest")
    value = hashlib.sha256(raw).hexdigest()
    if value != expected:
        refuse("stored generation data and SHA-256 disagree")
    return value


def logical_state(db: sqlite3.Connection) -> dict:
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN")
        if db.execute("PRAGMA integrity_check(1)").fetchone() != ("ok",):
            refuse("SQLite integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            refuse("SQLite foreign key check failed")
        versions = [row[0] for row in db.execute(
            "SELECT version FROM schema_migrations ORDER BY version")]
        if versions != list(range(1, 19)):
            refuse("unexpected SQLite migration history")
        state = db.execute(
            "SELECT config_revision, applied_generation_id, "
            "last_known_good_generation_id, recovery_required, "
            "core_desired_state, routing_mode, private_direct "
            "FROM daemon_state WHERE singleton=1").fetchall()
        if len(state) != 1:
            refuse("missing or duplicated daemon singleton")
        rev, applied, lkg, required, core, mode, private_direct = state[0]
        if (type(rev) is not int or rev < 0 or required not in (0, 1) or
                private_direct not in (0, 1) or core not in ("running", "stopped") or
                mode not in ("rule", "global", "direct")):
            refuse("invalid daemon fields")
        selection = db.execute(
            "SELECT revision, current_target_json FROM selection_state "
            "WHERE singleton=1").fetchall()
        if len(selection) != 1 or type(selection[0][0]) is not int or selection[0][0] < 0:
            refuse("invalid selection singleton")
        selected_revision, selected_raw = selection[0]
        if selected_raw is not None and not isinstance(selected_raw, bytes):
            refuse("selection payload is not bytes")
        active = db.execute(
            "SELECT id, phase FROM apply_journal WHERE active_slot=1").fetchall()
        if len(active) > 1:
            refuse("multiple active apply attempts")
        if active and active[0][1] not in (
                "prepared", "activating", "verifying", "rolling_back"):
            refuse("invalid active journal phase")
        pending = db.execute(
            "SELECT COUNT(*) FROM inert_restore_preparations WHERE phase='prepared'").fetchone()[0]
        if type(pending) is not int or pending < 0 or pending > 1:
            refuse("invalid independent restore journal")
        digests = []
        for gid in (applied, lkg):
            if gid is None:
                digests.append(None)
                continue
            if type(gid) is not int or gid <= 0:
                refuse("invalid generation id")
            row = db.execute(
                "SELECT config_json, config_sha256, manifest_json, manifest_sha256, "
                "source_map_json, source_map_sha256 FROM generations WHERE id=?", (gid,)
            ).fetchone()
            if row is None:
                refuse("applied/LKG generation payload missing")
            digests.append([
                sha_blob(row[0], row[1]),
                None if row[2] is None and row[3] is None else sha_blob(row[2], row[3]),
                None if row[4] is None and row[5] is None else sha_blob(row[4], row[5]),
            ])
        result = {
            "schema_version": 18,
            "config_revision": rev,
            "applied_generation_id": applied,
            "lkg_generation_id": lkg,
            "applied_and_lkg_sha256": digests,
            "core_desired_state": core,
            "routing_mode": mode,
            "private_direct": bool(private_direct),
            "selection_revision": selected_revision,
            "selection_sha256": None if selected_raw is None else hashlib.sha256(selected_raw).hexdigest(),
            "recovery_required": bool(required),
            "active_apply_attempt": None if not active else list(active[0]),
            "prepared_inert_restore_count": pending,
        }
        db.execute("COMMIT")
        return result
    except sqlite3.Error as exc:
        raise AuditRefusal("SQLite read-only consistency inspection refused") from exc


def observe_db(path: Path) -> dict:
    fd = private_fd(path, MAX_DB)
    try:
        # Read via SQLite's WAL-aware, READ-ONLY URI; do not use immutable=1
        # (which could silently ignore a relevant committed WAL transaction).
        if not file_identity(fd, path):
            refuse("SQLite inode changed before read")
        uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=0)) as db:
            value = logical_state(db)
        if not file_identity(fd, path):
            refuse("SQLite inode changed after read")
        return value
    finally:
        os.close(fd)


def strict_args(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.case not in vm.CASES or not vm.NONCE_RE.fullmatch(args.nonce):
        refuse("unsupported fault checkpoint or nonce")
    expected_ack = "GUEST_AUDIT:" + args.case + ":" + args.nonce
    if os.geteuid() == 0 or os.environ.get("KTUI_LAB_GUEST_AUDIT_ACK") != expected_ack:
        refuse("explicit disposable guest-only acknowledgement missing")
    state_base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    if not state_base.is_absolute() or ".." in state_base.parts:
        refuse("invalid XDG state root")
    app = state_base / "karing-tui-v2"
    witness = app / "recovery-lab" / ("ktui-powercut-disposable-" + args.nonce)
    if (str(args.witness) != str(witness) or str(witness) != os.path.realpath(witness) or
            str(app) != os.path.realpath(app)):
        refuse("witness escaped the dedicated disposable guest lab path")
    return witness, app / "state.db"


def write_private_baseline(parent: Path, name: str, report: dict) -> str:
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAX_WITNESS:
        refuse("baseline exceeded audit limit")
    fd = os.open(parent / name,
                 os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(raw)
            f.flush()
            os.fsync(fd)
        folder = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    finally:
        os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def inspect(args: argparse.Namespace) -> dict:
    witness, db_path = strict_args(args)
    with ExitStack() as stack:
        stack.callback(os.close, private_fd(witness, 0, directory=True))
        state = observe_db(db_path)
        baseline_name = "baseline-" + args.nonce + ".json"
        base_doc = {"format": VERSION, "case": args.case, "nonce": args.nonce, "state": state}
        if args.mode == "capture":
            digest = write_private_baseline(witness, baseline_name, base_doc)
            return {"status": "baseline_captured_no_reboot_claim", "baseline_sha256": digest,
                    "physical_power_loss_verified": False, "restore_authorized": False,
                    "metadata_deletion_authorized": False}
        if not SHA.fullmatch(args.baseline_sha256 or ""):
            refuse("expected offline-pinned baseline SHA-256 missing")
        baseline, baseline_hash = private_json(witness / baseline_name)
        if baseline_hash != args.baseline_sha256 or baseline.get("format") != VERSION or (
                baseline.get("case"), baseline.get("nonce")) != (args.case, args.nonce):
            refuse("baseline changed, invalid or not bound to this experiment")
        observation, _ = private_json(witness / ("observation-" + args.nonce + ".json"))
        if (observation.get("schema_version") != 1 or
                observation.get("status") != "virtual_guest_forced_off_observed" or
                observation.get("case") != args.case or observation.get("nonce") != args.nonce or
                observation.get("physical_power_loss_verified") is not False or
                observation.get("post_reboot_consistency_verified") is not False or
                observation.get("restore_authorized") is not False or
                observation.get("metadata_deletion_authorized") is not False):
            refuse("host witness is not a non-authorizing observed virtual stop")
        if baseline.get("state") != state:
            refuse("guest post-boot SQLite snapshot differs from trusted baseline")
        if state["recovery_required"] or state["active_apply_attempt"] is not None:
            refuse("unfinished apply recovery remains; manual incident review required")
        return {"status": "sqlite_subset_consistent_manual_review_only",
                "sqlite_subset_checked": True,
                "virtual_stop_witness_seen": True,
                "guest_reboot_verified": False,
                "physical_power_loss_verified": False,
                "core_health_verified": False,
                "archive_hmac_verified": False,
                "restore_authorized": False,
                "metadata_deletion_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("capture", "verify"))
    parser.add_argument("--case", required=True, choices=vm.CASES)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--baseline-sha256")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(inspect(args), sort_keys=True))
        return 0
    except (AuditRefusal, OSError, ValueError) as exc:
        # Secrets, actual filesystem paths, SQL statements and raw BLOBs
        # must never be printed on refusal.
        print("REFUSED: disposable guest SQLite post-boot audit is not trustworthy", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
