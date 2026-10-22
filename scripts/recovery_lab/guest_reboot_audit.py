#!/usr/bin/env python3
"""Read-only, disposable-guest SQLite replay preflight for T15/T23.

NEVER claims power-loss replay, Core health, or restore/delete authority.  This
tool assumes a separate guest test fixture and a user-session VM stop witness;
it neither boots a VM nor opens a write connection to the live SQLite state.
"""
from __future__ import annotations

import argparse
from contextlib import closing, ExitStack
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import quote, urlsplit

import vm_power_cut as vm

SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_DB = 64 << 20  # deliberately narrower than the application's 768 MiB archive bound
MAX_WITNESS = 16 << 10
VERSION = 12
MAX_HOST_RECEIPT = 4096
UTC_HOST_CLOCK = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00\Z")
MAX_PROFILE_SOURCE_ROWS = 64  # guest-only bounded source URL/schedule/lease/usage evidence
PROFILE_UPDATE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
MAX_PROFILE_OVERLAY_ROWS = 2048  # guest-only global bound; not production per-profile quota
MAX_PROFILE_OVERLAY_ALIAS_BYTES = 512
MAX_PROFILE_OVERLAY_SORT_RANK = (1 << 62) - 1
MAX_PROFILE_STATES = 64
MAX_PROFILE_SNAPSHOTS = 128
MAX_PROFILE_NODES = 8192
MAX_PROFILE_NODE_BYTES = 1 << 20
MAX_PROFILE_TOTAL_BYTES = 48 << 20  # disposable-guest-only, stricter than Go's per-snapshot limit
MAX_DECLARATION_ROWS = 128
MAX_DECLARATION_BYTES = 16 << 20
DECLARATION_SOURCE = re.compile(r"[A-Za-z0-9_./:-]{1,128}\Z")
MAX_GENERATION_ROWS = 128
MAX_GENERATION_CONFIG_BYTES = 64 << 20
MAX_GENERATION_METADATA_BYTES = 16 << 20
MAX_INERT_RESTORE_ROWS = 32
MAX_INERT_BASELINE_BYTES = 4096
MAX_INERT_ARCHIVE_BYTES = 2 << 30
INERT_SCOPE_RE = re.compile(r"\.ktui-restore-v1-[A-Za-z0-9]{6,32}\Z")
MAX_HISTORY_ROWS = 512  # guest-only bounded archival audit, not a production GC budget
MAX_HISTORY_ERROR_BYTES = 4096


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


def private_json_at(dfd: int, name: str, maximum=MAX_WITNESS) -> tuple[dict, str]:
    # All witness reads are descriptor-relative to the same private directory
    # that was validated before the SQLite inspection. No path-based reopen.
    if not re.fullmatch(r"(baseline|intent|observation|poststart|boot-epoch)-[0-9a-f]{32}\.json", name):
        refuse("invalid witness name")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            info = os.fstat(fd)
            named = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or
                    not 0 < info.st_size <= maximum or
                    (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                refuse("invalid private witness identity")
            raw = os.pread(fd, maximum + 1, 0)
            later = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (len(raw) != info.st_size or
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                    (later.st_dev, later.st_ino, later.st_size, later.st_mtime_ns)):
                refuse("witness changed while being read")
            # The host writer never emits duplicate keys or NaN/Infinity.
            # JSON decoders can disagree about those ambiguous records; reject
            # them in all baselines and host-stop receipts before binding SHA.
            def unique_object(fields):
                value = dict(fields)
                if len(value) != len(fields):
                    refuse("ambiguous duplicate private witness JSON key")
                return value

            doc = json.loads(
                raw, object_pairs_hook=unique_object,
                parse_constant=lambda _: refuse("non-finite private witness value"))
            if not isinstance(doc, dict):
                refuse("witness must be a JSON object")
            return doc, hashlib.sha256(raw).hexdigest()
        finally:
            os.close(fd)
    except (ValueError, UnicodeError, OSError) as exc:
        raise AuditRefusal("invalid private witness") from exc


def sha_blob(raw, expected) -> str:
    if not isinstance(raw, bytes) or not isinstance(expected, str) or not SHA.fullmatch(expected):
        refuse("missing or noncanonical generation digest")
    value = hashlib.sha256(raw).hexdigest()
    if value != expected:
        refuse("stored generation data and SHA-256 disagree")
    return value



def archived_history_ledger(db: sqlite3.Connection) -> tuple[int, dict | None, str]:
    """Hash all bounded archived attempts; do not expose error text or secrets."""
    # LIMIT makes the total history read bounded even when a guest contains
    # unexpected old rows. Truncate SQL error text before Python sees it.
    rows = db.execute(
        "SELECT id, generation_id, previous_generation_id, base_revision, "
        "target_revision, phase, config_sha256, manifest_sha256, "
        "source_map_sha256, substr(error,1,4097), length(error), "
        "started_at, updated_at, generation_created_at, archived_at "
        "FROM apply_history ORDER BY id LIMIT ?",
        (MAX_HISTORY_ROWS + 1,)).fetchall()
    if len(rows) > MAX_HISTORY_ROWS:
        refuse("disposable guest archived history exceeds bounded audit limit")
    digest = hashlib.sha256()
    last = None
    previous_id = 0
    for row in rows:
        (rid, generation, previous, base, target, phase, cfg, manifest, source,
         error_text, error_length, started, updated, created, archived) = row
        if (type(rid) is not int or rid <= previous_id or
                type(generation) is not int or generation <= 0 or
                (previous is not None and (type(previous) is not int or previous <= 0)) or
                type(base) is not int or base < 0 or
                type(target) is not int or target != base + 1 or
                phase not in ("committed", "rolled_back", "failed", "interrupted") or
                not isinstance(cfg, str) or not SHA.fullmatch(cfg) or
                (manifest is not None and
                 (not isinstance(manifest, str) or not SHA.fullmatch(manifest))) or
                (source is not None and
                 (not isinstance(source, str) or not SHA.fullmatch(source))) or
                type(error_length) is not int or error_length < 0 or
                error_length > MAX_HISTORY_ERROR_BYTES or
                not isinstance(error_text, str) or
                len(error_text.encode("utf-8")) > MAX_HISTORY_ERROR_BYTES):
            refuse("invalid archived apply row")
        for stamp in (started, updated, created, archived):
            if (not isinstance(stamp, str) or not stamp.isascii() or
                    not 0 < len(stamp) <= 96):
                refuse("invalid archived apply timestamp")
        # No original free-text SQL error, config BLOB or timestamps are
        # disclosed; the entire canonical record is covered by this digest.
        packed = [rid, generation, previous, base, target, phase, cfg,
                  manifest, source, error_text, started, updated, created, archived]
        digest.update(json.dumps(packed, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        digest.update(b"\n")
        previous_id = rid
        last = {
            "id": rid,
            "generation_id": generation,
            "target_revision": target,
            "phase": phase,
            "digests": [cfg, manifest, source],
        }
    return len(rows), last, digest.hexdigest()




# Exact exported Go storage.InertRestoreFence field order. json.Marshal on this
# struct emits the keys in this order with no whitespace. Never accept an
# arbitrary newly SHA-rehashed JSON object as a persisted Go CAS baseline.
GO_FENCE_FIELDS = (
    "ConfigRevision", "AppliedGenerationID", "LastKnownGoodGenerationID",
    "DeclarationRevision", "DeclarationSHA256",
    "SelectionRevision", "SelectionSHA256",
    "RoutingMode", "PrivateDirect", "CoreDesiredState",
    "AppliedConfigSHA256", "AppliedManifestSHA256", "AppliedSourceMapSHA256",
    "LastKnownGoodConfigSHA256", "LastKnownGoodManifestSHA256",
    "LastKnownGoodSourceMapSHA256",
)
GO_FENCE_SHA_FIELDS = (
    "DeclarationSHA256", "SelectionSHA256",
    "AppliedConfigSHA256", "AppliedManifestSHA256", "AppliedSourceMapSHA256",
    "LastKnownGoodConfigSHA256", "LastKnownGoodManifestSHA256",
    "LastKnownGoodSourceMapSHA256",
)


def canonical_go_inert_fence(raw: bytes) -> None:
    """Refuse forged fields/encoding; this is still NOT a restore permit."""
    try:
        data = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise AuditRefusal("invalid inert restore fence JSON") from exc
    if not isinstance(data, dict) or tuple(data) != GO_FENCE_FIELDS:
        refuse("inert restore fence fields differ from the Go v18 record")
    # Python bool is an int subclass. Type-exact checks are essential here.
    maximum = (1 << 63) - 1
    for key, minimum, inclusive_maximum in (
        ("ConfigRevision", 1, maximum - 1),
        ("AppliedGenerationID", 1, maximum),
        ("LastKnownGoodGenerationID", 1, maximum),
        ("DeclarationRevision", 1, maximum),
        ("SelectionRevision", 0, maximum),
    ):
        value = data[key]
        if type(value) is not int or not minimum <= value <= inclusive_maximum:
            refuse("inert restore fence integer outside Go-compatible bounds")
    for key in GO_FENCE_SHA_FIELDS:
        value = data[key]
        if not isinstance(value, str) or not SHA.fullmatch(value):
            refuse("inert restore fence contains noncanonical digest")
    if (data["RoutingMode"] not in ("rule", "global", "direct") or
            data["CoreDesiredState"] not in ("stopped", "running") or
            type(data["PrivateDirect"]) is not bool):
        refuse("inert restore fence has invalid routing or Core intent")
    # Every permitted value is ASCII, and the bytes must match Go's compact,
    # ordered json.Marshal encoding. This rejects duplicate/unknown keys,
    # whitespace, alternate key ordering, floats and escape aliases even
    # when the attacker also recalculates baseline_sha256.
    try:
        encoded = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise AuditRefusal("unable to canonicalize inert restore fence") from exc
    if encoded != raw:
        refuse("inert restore fence is not the canonical Go JSON encoding")


def inert_restore_journal_ledger(db: sqlite3.Connection) -> tuple[int, int, str]:
    """Inspect only inert v18 metadata; never authorize candidate restoration."""
    rows = db.execute(
        "SELECT id, candidate_scope, archive_sha256, inventory_sha256, "
        "archive_bytes, baseline_json, baseline_sha256, phase, active_slot, "
        "created_at, updated_at FROM inert_restore_preparations "
        "ORDER BY id LIMIT ?",
        (MAX_INERT_RESTORE_ROWS + 1,)).fetchall()
    if len(rows) > MAX_INERT_RESTORE_ROWS:
        refuse("disposable inert restore journal exceeds private audit budget")
    checksum = hashlib.sha256()
    last_id = 0
    pending = 0
    for row in rows:
        (rid, scope, archive_sha, inventory_sha, archive_bytes, fence_json,
         fence_sha, phase, active_slot, created, updated) = row
        if (type(rid) is not int or rid <= last_id or
                not isinstance(scope, str) or not INERT_SCOPE_RE.fullmatch(scope) or
                not isinstance(archive_sha, str) or not SHA.fullmatch(archive_sha) or
                not isinstance(inventory_sha, str) or not SHA.fullmatch(inventory_sha) or
                type(archive_bytes) is not int or
                not 0 < archive_bytes <= MAX_INERT_ARCHIVE_BYTES or
                not isinstance(fence_json, bytes) or
                not 0 < len(fence_json) <= MAX_INERT_BASELINE_BYTES or
                not isinstance(fence_sha, str) or not SHA.fullmatch(fence_sha) or
                phase not in ("prepared", "abandoned")):
            refuse("malformed inert restore journal identity")
        sha_blob(fence_json, fence_sha)
        canonical_go_inert_fence(fence_json)
        if phase == "prepared":
            if type(active_slot) is not int or active_slot != 1:
                refuse("pending inert restore journal missing active slot")
            pending += 1
        elif active_slot is not None:
            refuse("abandoned inert restore journal still occupies active slot")
        if pending > 1:
            refuse("more than one inert restore candidate is pending")
        times = []
        for stamp in (created, updated):
            if (not isinstance(stamp, str) or not stamp.isascii() or
                    not 0 < len(stamp) <= 96):
                refuse("invalid inert restore timestamps")
            try:
                parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise AuditRefusal("invalid inert restore timestamp") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                refuse("inert restore timestamp lacks timezone")
            times.append(parsed)
        if times[1] < times[0]:
            refuse("inert restore journal was updated before creation")
        # These are ALL durable row fields. The report/witness contains only
        # the SHA: no restore candidate scope, fence JSON or archive contents.
        packed = [rid, scope, archive_sha, inventory_sha, archive_bytes,
                  fence_sha, phase, active_slot, created, updated]
        checksum.update(json.dumps(
            packed, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        checksum.update(b"\n")
        last_id = rid
    return len(rows), pending, checksum.hexdigest()



def complete_generation_ledger(db: sqlite3.Connection) -> tuple[int, str]:
    """Read-only v18 audit of EVERY retained generation, including orphans."""
    # Full config/source JSON is never exported. The caller already pinned a
    # <=64 MiB private main database and reads one WAL-aware SQLite snapshot.
    rows = db.execute(
        "SELECT id, base_revision, target_revision, config_json, config_sha256, "
        "manifest_json, manifest_sha256, source_map_json, source_map_sha256, "
        "created_at, restore_origin_generation_id FROM generations ORDER BY id LIMIT ?",
        (MAX_GENERATION_ROWS + 1,)).fetchall()
    if len(rows) > MAX_GENERATION_ROWS:
        refuse("guest retained generation count exceeds bounded audit limit")
    digest = hashlib.sha256()
    previous_id = 0

    def hashed_json(raw, expected, maximum):
        if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
            refuse("missing or oversized retained generation JSON")
        digest_value = sha_blob(raw, expected)
        try:
            json.loads(raw, parse_constant=lambda _: refuse(
                "non-JSON constant in retained generation"))
        except (ValueError, UnicodeError) as exc:
            raise AuditRefusal("invalid retained generation JSON") from exc
        return digest_value

    for row in rows:
        (gid, base, target, config, config_sha,
         manifest, manifest_sha, source_map, source_sha, created, restore_origin) = row
        if (type(gid) is not int or gid <= previous_id or
                type(base) is not int or base < 0 or
                type(target) is not int or target != base + 1 or
                (restore_origin is not None and
                 (type(restore_origin) is not int or restore_origin <= 0))):
            refuse("invalid retained generation ID or revision")
        cfg_digest = hashed_json(
            config, config_sha, MAX_GENERATION_CONFIG_BYTES)
        other_digests = []
        lengths = [len(config)]
        for raw, sha in ((manifest, manifest_sha), (source_map, source_sha)):
            if raw is None and sha is None:
                other_digests.append(None)
                lengths.append(0)
            elif raw is None or sha is None:
                refuse("retained generation metadata BLOB/hash mismatch")
            else:
                other_digests.append(
                    hashed_json(raw, sha, MAX_GENERATION_METADATA_BYTES))
                lengths.append(len(raw))
        if (not isinstance(created, str) or not created.isascii() or
                not 0 < len(created) <= 96):
            refuse("invalid retained generation creation timestamp")
        try:
            instant = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditRefusal("invalid retained generation creation time") from exc
        if instant.tzinfo is None or instant.utcoffset() is None:
            refuse("retained generation timestamp lacks timezone")
        # Ordered canonical metadata covers full BLOB digests and lengths.
        # No secret-containing config, scope, paths or timestamps are printed.
        packed = [gid, base, target, cfg_digest, other_digests[0],
                  other_digests[1], lengths, created, restore_origin]
        digest.update(json.dumps(
            packed, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        digest.update(b"\n")
        previous_id = gid
    return len(rows), digest.hexdigest()



def complete_declaration_ledger(db: sqlite3.Connection) -> tuple[int, int | None, str]:
    """Read-only audit of the entire v18 declaration revision chain."""
    state = db.execute(
        "SELECT current_revision FROM declaration_state WHERE singleton=1").fetchall()
    if len(state) != 1:
        refuse("invalid declaration singleton")
    current = state[0][0]
    if current is not None and (type(current) is not int or current <= 0):
        refuse("invalid current declaration revision")
    rows = db.execute(
        "SELECT revision, parent_revision, document_json, document_sha256, "
        "source, created_at FROM declaration_revisions ORDER BY revision LIMIT ?",
        (MAX_DECLARATION_ROWS + 1,)).fetchall()
    if len(rows) > MAX_DECLARATION_ROWS:
        refuse("disposable declaration history exceeds bounded audit limit")
    checksum = hashlib.sha256()
    for n, row in enumerate(rows, start=1):
        rev, parent, raw, stored_sha, source, created = row
        if (type(rev) is not int or rev != n or
                parent != (None if n == 1 else n - 1) or
                (parent is not None and type(parent) is not int) or
                not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_DECLARATION_BYTES or
                not isinstance(source, str) or not DECLARATION_SOURCE.fullmatch(source)):
            refuse("invalid declaration revision chain or source")
        digest = sha_blob(raw, stored_sha)
        try:
            json.loads(raw, parse_constant=lambda _: refuse(
                "non-JSON declaration literal"))
        except (UnicodeError, ValueError) as exc:
            raise AuditRefusal("invalid retained declaration JSON") from exc
        if (not isinstance(created, str) or not created.isascii() or
                not 0 < len(created) <= 96):
            refuse("invalid declaration timestamp")
        try:
            when = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditRefusal("invalid declaration timestamp") from exc
        if when.tzinfo is None or when.utcoffset() is None:
            refuse("declaration timestamp missing timezone")
        # Only canonical private digests are retained, never native
        # policy/DNS documents, profile credentials or source names.
        record = [rev, parent, digest, len(raw), source, created]
        checksum.update(json.dumps(
            record, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        checksum.update(b"\n")
    expected_current = len(rows) if rows else None
    if current != expected_current:
        refuse("current declaration pointer does not match retained revision chain")
    return len(rows), current, checksum.hexdigest()


def complete_profile_snapshot_ledger(db: sqlite3.Connection) -> tuple[int, int, int, str]:
    """Bounded v18 profile snapshot and node evidence, without exporting credentials.

    The Go Store retains current+previous snapshots per profile, not unbounded
    history. Source URL/fetch state remains outside this ledger; separately
    persisted node user overlays are pinned by another bounded ledger below.
    """
    def bounded_text(value, maximum, required=True, trimmed=True):
        if (not isinstance(value, str) or
                (required and not value) or len(value.encode("utf-8")) > maximum or
                (trimmed and value.strip() != value) or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            refuse("invalid retained profile identity or metadata")

    def bounded_time(value):
        if (not isinstance(value, str) or not value.isascii() or
                not 0 < len(value) <= 96):
            refuse("invalid retained profile timestamp")
        try:
            instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditRefusal("invalid retained profile timestamp") from exc
        if instant.tzinfo is None or instant.utcoffset() is None:
            refuse("retained profile timestamp lacks timezone")

    digest = hashlib.sha256()

    def pin(kind, fields):
        digest.update(kind.encode("ascii"))
        digest.update(json.dumps(
            fields, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        digest.update(b"\n")

    state_rows = db.execute(
        "SELECT profile_id, current_snapshot_id, previous_snapshot_id, "
        "updated_at FROM profile_state ORDER BY profile_id LIMIT ?",
        (MAX_PROFILE_STATES + 1,)).fetchall()
    if len(state_rows) > MAX_PROFILE_STATES:
        refuse("too many guest profile state rows")
    state_by_profile = {}
    referenced = set()
    for profile_id, current, previous, updated in state_rows:
        bounded_text(profile_id, 512)
        if (type(current) is not int or current <= 0 or
                (previous is not None and
                 (type(previous) is not int or previous <= 0 or previous >= current))):
            refuse("invalid guest profile current/previous snapshot pointers")
        bounded_time(updated)
        state_by_profile[profile_id] = (current, previous)
        referenced.add(current)
        if previous is not None:
            referenced.add(previous)
        pin("S", [profile_id, current, previous, updated])

    snapshot_rows = db.execute(
        "SELECT id, profile_id, source_kind, source_revision, "
        "source_sha256, created_at FROM profile_snapshots ORDER BY id LIMIT ?",
        (MAX_PROFILE_SNAPSHOTS + 1,)).fetchall()
    if len(snapshot_rows) > MAX_PROFILE_SNAPSHOTS:
        refuse("too many retained guest profile snapshots")
    snapshots = {}
    previous_id = 0
    for sid, profile_id, kind, source_revision, source_sha, created in snapshot_rows:
        if (type(sid) is not int or sid <= previous_id or
                sid not in referenced or profile_id not in state_by_profile or
                sid not in state_by_profile[profile_id] or
                not isinstance(source_sha, str) or not SHA.fullmatch(source_sha)):
            refuse("invalid retained guest profile snapshot owner or source hash")
        bounded_text(profile_id, 512)
        bounded_text(kind, 128)
        bounded_text(source_revision, 4096, required=False)
        bounded_time(created)
        snapshots[sid] = profile_id
        pin("P", [sid, profile_id, kind, source_revision, source_sha, created])
        previous_id = sid
    if set(snapshots) != referenced:
        refuse("profile snapshot pointer or retained snapshot is missing")

    # Iterate one row at a time; do not materialize thousands of 1 MiB secret
    # node JSON documents in memory or put them in witness/report fields.
    ordinals = {sid: 0 for sid in snapshots}
    per_snapshot_bytes = {sid: 0 for sid in snapshots}
    total_nodes = 0
    total_bytes = 0
    cursor = db.execute(
        "SELECT snapshot_id, ordinal, node_id, source_key, source_name, "
        "payload_json, payload_sha256 "
        "FROM profile_snapshot_nodes ORDER BY snapshot_id, ordinal")
    for sid, ordinal, node_id, source_key, source_name, raw, stored_sha in cursor:
        total_nodes += 1
        if total_nodes > MAX_PROFILE_NODES:
            refuse("too many retained guest snapshot nodes")
        if (type(sid) is not int or sid not in snapshots or
                type(ordinal) is not int or ordinal != ordinals[sid]):
            refuse("invalid guest snapshot node owner or ordinal")
        bounded_text(node_id, 512)
        bounded_text(source_key, 4096)
        bounded_text(source_name, 4096, trimmed=False)
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PROFILE_NODE_BYTES:
            refuse("missing or oversized guest snapshot node JSON")
        total_bytes += len(raw)
        per_snapshot_bytes[sid] += len(raw)
        if (total_bytes > MAX_PROFILE_TOTAL_BYTES or
                per_snapshot_bytes[sid] > (64 << 20)):
            refuse("guest profile snapshot payload budget exceeded")
        payload_sha = sha_blob(raw, stored_sha)
        try:
            json.loads(raw, parse_constant=lambda _: refuse(
                "non-JSON constant in guest snapshot node"))
        except (UnicodeError, ValueError) as exc:
            raise AuditRefusal("invalid guest snapshot node JSON") from exc
        pin("N", [sid, ordinal, node_id, source_key, source_name,
                  payload_sha, len(raw)])
        ordinals[sid] += 1

    return len(state_rows), len(snapshot_rows), total_nodes, digest.hexdigest()


def complete_profile_overlay_ledger(db: sqlite3.Connection) -> tuple[int, str]:
    """Pin all retained node user overlays, including detached/dormant IDs.

    Go intentionally retains overlays for nodes removed from a newer snapshot.
    Therefore do NOT require node_id to exist in current/previous snapshots:
    this would silently lose the exact dormant user intent we must audit.
    """
    def stable_id(value):
        if (not isinstance(value, str) or not value or
                len(value.encode("utf-8")) > 512 or value.strip() != value or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            refuse("invalid persisted profile overlay identity")

    def overlay_alias(value):
        if (not isinstance(value, str) or
                len(value.encode("utf-8")) > MAX_PROFILE_OVERLAY_ALIAS_BYTES or
                value.strip() != value or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            refuse("invalid persisted profile overlay alias")

    rows = db.execute(
        "SELECT profile_id, node_id, revision, disabled, favorite, "
        "alias, sort_rank, updated_at FROM profile_node_overlays "
        "ORDER BY profile_id, node_id LIMIT ?",
        (MAX_PROFILE_OVERLAY_ROWS + 1,)).fetchall()
    if len(rows) > MAX_PROFILE_OVERLAY_ROWS:
        refuse("guest profile overlays exceed bounded audit limit")
    digest = hashlib.sha256()
    digest.update(b"ktui/guest-v9/profile-overlay-rows\0")
    previous = None
    for profile_id, node_id, revision, disabled, favorite, alias, sort_rank, updated in rows:
        stable_id(profile_id)
        stable_id(node_id)
        overlay_alias(alias)
        identity = (profile_id, node_id)
        if (previous is not None and identity <= previous or
                type(revision) is not int or revision <= 0 or
                type(disabled) is not int or disabled not in (0, 1) or
                type(favorite) is not int or favorite not in (0, 1) or
                (sort_rank is not None and
                 (type(sort_rank) is not int or
                  not 0 <= sort_rank <= MAX_PROFILE_OVERLAY_SORT_RANK))):
            refuse("invalid persisted profile overlay revision, flags, rank or order")
        if (not isinstance(updated, str) or not updated.isascii() or
                not 0 < len(updated) <= 96):
            refuse("invalid persisted profile overlay timestamp")
        try:
            instant = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditRefusal("invalid persisted profile overlay timestamp") from exc
        if instant.tzinfo is None or instant.utcoffset() is None:
            refuse("profile overlay timestamp must include timezone")
        # Entire row is pinned, but private alias and IDs never appear in
        # baseline/report plaintext or errors (only count + ordered digest).
        record = [profile_id, node_id, revision, disabled, favorite,
                  alias, sort_rank, updated]
        digest.update(json.dumps(
            record, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        digest.update(b"\n")
        previous = identity
    return len(rows), digest.hexdigest()


def complete_profile_source_ledger(db: sqlite3.Connection) -> tuple[int, str]:
    """Complete bounded v18 source-spec, fetch/lease and usage ledger.

    A source may exist before ANY profile snapshot and a snapshot may
    outlive its source. No artificial FK to profile_state is imposed.
    Credentials, source URLs and mutable HTTP metadata never leave the
    transaction except through the private SHA-256 ledger.
    """
    def bounded_text(value, limit, required=False, trimmed=False):
        if (not isinstance(value, str) or
                (required and not value) or len(value.encode("utf-8")) > limit or
                (trimmed and value.strip() != value) or
                any(ord(c) < 32 or ord(c) == 127 for c in value)):
            refuse("invalid persisted profile source text")

    def source_time(value, optional=False, expiry=False):
        if value is None and optional:
            return
        if (not isinstance(value, str) or not value.isascii() or
                len(value) > 96 or not re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
                    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value)):
            refuse("invalid persisted profile source timestamp")
        try:
            instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditRefusal("invalid persisted profile source timestamp") from exc
        if instant.tzinfo is None or instant.utcoffset() is None or (
                expiry and instant.year < 1970):
            refuse("invalid persisted profile source timestamp or expiry")

    columns = (
        "profile_id", "revision", "source_format", "location_kind", "location",
        "user_agent", "fetch_mode", "fetch_profile_id", "fetch_node_id",
        "filter_method", "filter_expression", "filter_match_attribute",
        "enabled", "update_interval_seconds", "created_at", "updated_at",
        "last_attempt_at", "last_success_at", "last_error",
        "last_source_revision", "etag", "last_modified",
        "subscription_upload_bytes", "subscription_download_bytes",
        "subscription_total_bytes", "subscription_expires_at",
        "subscription_usage_updated_at", "subscription_metadata_observed_at",
        "subscription_metadata_error", "consecutive_failures",
        "retry_after_at", "active_update_id", "active_update_started_at",
    )
    rows = db.execute(
        "SELECT " + ", ".join(columns) +
        " FROM profile_sources ORDER BY profile_id LIMIT ?",
        (MAX_PROFILE_SOURCE_ROWS + 1,)).fetchall()
    if len(rows) > MAX_PROFILE_SOURCE_ROWS:
        refuse("guest profile sources exceed bounded audit limit")

    digest = hashlib.sha256()
    digest.update(b"ktui/guest-v10/profile-source-rows\0")
    previous = None
    lease_ids = set()
    for row in rows:
        (pid, revision, fmt, kind, location, user_agent, fetch_mode,
         fetch_profile, fetch_node, filter_method, filter_expr,
         filter_attribute, enabled, interval, created, updated,
         last_attempt, last_success, last_error, source_revision, etag,
         last_modified, upload, download, total, expires, usage_updated,
         metadata_observed, metadata_error, failures, retry_after,
         active_id, active_started) = row
        bounded_text(pid, 512, required=True, trimmed=True)
        if (previous is not None and pid <= previous or
                type(revision) is not int or revision <= 0 or
                fmt not in ("sing-box", "uri-list", "uri-list-base64") or
                kind not in ("url", "file")):
            refuse("invalid persisted profile source identity or revision")
        bounded_text(location, 8192, required=True, trimmed=True)
        if kind == "url":
            try:
                url = urlsplit(location)
                hostname = url.hostname
            except ValueError as exc:
                raise AuditRefusal("invalid profile source URL") from exc
            if (url.scheme not in ("http", "https") or not hostname or
                    "@" in url.netloc):
                refuse("invalid profile source URL")
        else:
            # Linux-only source model: Go filepath.Clean rejects unclean paths.
            if (not os.path.isabs(location) or
                    os.path.normpath(location) != location):
                refuse("invalid profile source file path")
        bounded_text(user_agent, 1024)
        if fetch_mode in ("direct", "selected"):
            if fetch_profile != "" or fetch_node != "":
                refuse("unbound profile fetch mode contains node reference")
        elif fetch_mode == "specific_node":
            bounded_text(fetch_profile, 512, required=True, trimmed=True)
            bounded_text(fetch_node, 512, required=True, trimmed=True)
        else:
            refuse("unsupported persisted profile fetch mode")
        if kind == "file" and fetch_mode != "direct":
            refuse("local file source requires direct fetch")
        if filter_method not in ("", "include", "exclude"):
            refuse("invalid persisted profile filter mode")
        bounded_text(filter_expr, 4096, trimmed=True)
        if (type(filter_attribute) is not int or
                filter_attribute not in (0, 1) or
                type(enabled) is not int or enabled not in (0, 1) or
                type(interval) is not int or
                (interval != 0 and
                 (kind != "url" or not 300 <= interval <= 31536000))):
            refuse("invalid profile source filter, enabled or schedule")
        source_time(created)
        source_time(updated)
        for timestamp in (last_attempt, last_success, retry_after,
                          usage_updated, metadata_observed):
            source_time(timestamp, optional=True)
        source_time(expires, optional=True, expiry=True)
        for value, maximum in ((last_error, 8192),
                               (source_revision, 4096), (etag, 4096),
                               (last_modified, 4096),
                               (metadata_error, 2048)):
            bounded_text(value, maximum)
        if type(failures) is not int or not 0 <= failures <= 0xffffffff:
            refuse("invalid persisted profile update failure count")
        for byte_count in (upload, download, total):
            if byte_count is not None and (
                    type(byte_count) is not int or byte_count < 0):
                refuse("invalid persisted subscription usage bytes")
        if any(v is not None for v in (
                upload, download, total, expires)) and usage_updated is None:
            refuse("subscription usage has no observation timestamp")
        if (active_id is None) != (active_started is None):
            refuse("invalid persisted profile update lease pair")
        if active_id is not None:
            if (not isinstance(active_id, str) or
                    not PROFILE_UPDATE_ID.fullmatch(active_id) or
                    active_id in lease_ids or enabled != 1):
                refuse("invalid or duplicate persisted profile update lease")
            source_time(active_started)
            lease_ids.add(active_id)
        # Include all 33 raw stored values, including NULL-vs-empty distinctions;
        # no separate mutable filter/source/scheduler field can escape the pin.
        digest.update(json.dumps(
            list(row), separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        digest.update(b"\n")
        previous = pid
    return len(rows), digest.hexdigest()


def private_phase_marker_at(dfd: int, args: argparse.Namespace) -> str:
    """Bind the durable phase marker to the independently pinned baseline.

    The matching host vm_power_cut.py tool reads this marker; presence alone
    is not proof of checkpoint fidelity, VM boot or electrical power loss.
    """
    name = "ready-" + args.nonce + ".txt"
    expected = vm.marker_body(args.case, args.nonce)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            info = os.fstat(fd)
            first = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or
                    info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or
                    info.st_nlink != 1 or
                    info.st_size != len(expected) or
                    info.st_size > vm.MAX_MARKER or
                    (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns) !=
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)):
                refuse("invalid private guest phase marker")
            raw = os.pread(fd, vm.MAX_MARKER + 1, 0)
            last = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (raw != expected or
                    (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns) !=
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)):
                refuse("guest phase marker changed or mismatched")
            return hashlib.sha256(raw).hexdigest()
        finally:
            os.close(fd)
    except OSError as exc:
        raise AuditRefusal("missing or unsafe guest phase marker") from exc


def host_stop_chain_at(dfd: int, args: argparse.Namespace,
                       pinned_marker_sha: str) -> tuple[str, str]:
    """Verify host-produced durable intent and observed-stop receipts as a pair.

    These operator-writable records cannot certify a real reboot, disk
    durability, physical power loss or Core health.
    """
    if not SHA.fullmatch(pinned_marker_sha):
        refuse("no independently pinned phase-marker digest")
    fixed = {
        "schema_version": 1, "case": args.case, "nonce": args.nonce,
        "domain": args.domain, "domain_uuid": args.uuid,
        "marker_sha256": pinned_marker_sha,
        "guest_boot_verified": False,
        "post_reboot_consistency_verified": False,
        "physical_power_loss_verified": False,
        "restore_authorized": False,
        "metadata_deletion_authorized": False,
    }

    def strict_receipt(kind, status):
        record, digest = private_json_at(
            dfd, kind + "-" + args.nonce + ".json", maximum=MAX_HOST_RECEIPT)
        if (set(record) != set(fixed) | {"status", "time_utc"} or
                record.get("status") != status or
                any(record.get(key) != value or
                    (isinstance(value, (bool, int)) and
                     type(record.get(key)) is not type(value))
                    for key, value in fixed.items())):
            refuse("host stop receipt is not bound to this phase and VM")
        stamp = record.get("time_utc")
        if not isinstance(stamp, str) or not UTC_HOST_CLOCK.fullmatch(stamp):
            refuse("host stop receipt has no canonical UTC timestamp")
        try:
            when = datetime.fromisoformat(stamp)
        except ValueError as exc:
            raise AuditRefusal("invalid host stop timestamp") from exc
        return digest, when

    intent_sha, intent_time = strict_receipt(
        "intent", "intent_before_forced_virtual_stop")
    observed_sha, observed_time = strict_receipt(
        "observation", "virtual_guest_forced_off_observed")
    if observed_time < intent_time:
        refuse("host stop observation predates durable intent")
    return intent_sha, observed_sha


def host_poststart_at(dfd: int, args: argparse.Namespace, marker_sha: str,
                      baseline_sha: str, host_chain: tuple[str, str]) -> str:
    """Bind the separate *read-only host* running-state observation.

    All of these receipts remain operator-writable. This verifies strictly
    local record continuity, NOT reboot, electricity, Core or restoration.
    """
    record, post_sha = private_json_at(
        dfd, "poststart-" + args.nonce + ".json", maximum=MAX_HOST_RECEIPT)
    fixed = {
        "schema_version": 1,
        "status": "virtual_guest_running_observed_after_forced_off",
        "case": args.case, "nonce": args.nonce,
        "domain": args.domain, "domain_uuid": args.uuid,
        "marker_sha256": marker_sha, "baseline_sha256": baseline_sha,
        "intent_sha256": host_chain[0],
        "observation_sha256": host_chain[1],
        "guest_boot_verified": False,
        "post_reboot_consistency_verified": False,
        "physical_power_loss_verified": False,
        "core_health_verified": False,
        "archive_hmac_verified": False,
        "restore_authorized": False,
        "metadata_deletion_authorized": False,
    }
    if (set(record) != set(fixed) | {"time_utc"} or
            any(type(record.get(key)) is not type(value) or
                record.get(key) != value for key, value in fixed.items())):
        refuse("host running observation is not bound to pinned guest evidence")
    post_stamp = record.get("time_utc")
    if not isinstance(post_stamp, str) or not UTC_HOST_CLOCK.fullmatch(post_stamp):
        refuse("invalid host running-observation UTC timestamp")
    try:
        post_time = datetime.fromisoformat(post_stamp)
    except ValueError as exc:
        raise AuditRefusal("invalid host running-observation time") from exc
    previous_stop, previous_sha = private_json_at(
        dfd, "observation-" + args.nonce + ".json", maximum=MAX_HOST_RECEIPT)
    if previous_sha != host_chain[1]:
        refuse("host stop record changed before running observation comparison")
    earlier_stamp = previous_stop.get("time_utc")
    if not isinstance(earlier_stamp, str) or not UTC_HOST_CLOCK.fullmatch(earlier_stamp):
        refuse("invalid original host stop timestamp")
    if post_time < datetime.fromisoformat(earlier_stamp):
        refuse("running observation predates original observed host stop")
    return post_sha


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
        inert_count, pending, inert_ledger_sha = inert_restore_journal_ledger(db)
        # Go's bounded generation retention moves completed attempts to
        # apply_history BEFORE it admits the next prepared apply. The original
        # committed row is not expected to remain in apply_journal.
        history_count, latest_history, history_sha = archived_history_ledger(db)
        # Inspect the newest journal candidate as well as the confirmed
        # generation.  A prepared T15 fixture is NOT verified merely because
        # the applied generation remained sound: its unactivated candidate
        # and journal identity must also survive the recovery boundary.
        journal_count = db.execute("SELECT COUNT(*) FROM apply_journal").fetchone()[0]
        if type(journal_count) is not int or journal_count < 0:
            refuse("invalid apply journal count")
        latest = None
        tail = db.execute(
            "SELECT id, generation_id, previous_generation_id, "
            "base_revision, target_revision, phase, active_slot, error "
            "FROM apply_journal ORDER BY id DESC LIMIT 1").fetchall()
        if tail:
            (jid, candidate_id, previous_id, base_rev, target_rev,
             phase, active_slot, reason) = tail[0]
            valid_phases = ("prepared", "activating", "verifying", "rolling_back",
                            "committed", "rolled_back", "failed", "interrupted")
            if (type(jid) is not int or jid <= 0 or
                    type(candidate_id) is not int or candidate_id <= 0 or
                    (previous_id is not None and
                     (type(previous_id) is not int or previous_id <= 0)) or
                    type(base_rev) is not int or base_rev < 0 or
                    type(target_rev) is not int or target_rev != base_rev + 1 or
                    active_slot not in (None, 1) or
                    phase not in valid_phases or not isinstance(reason, str)):
                refuse("invalid most recent apply journal")
            candidate = db.execute(
                "SELECT config_json, config_sha256, manifest_json, manifest_sha256, "
                "source_map_json, source_map_sha256 FROM generations WHERE id=?",
                (candidate_id,)).fetchone()
            if candidate is None:
                refuse("latest apply candidate generation missing")
            latest = {
                "id": jid,
                "generation_id": candidate_id,
                "previous_generation_id": previous_id,
                "base_revision": base_rev,
                "target_revision": target_rev,
                "phase": phase,
                "active": active_slot == 1,
                "candidate_sha256": [
                    sha_blob(candidate[0], candidate[1]),
                    None if candidate[2] is None and candidate[3] is None
                    else sha_blob(candidate[2], candidate[3]),
                    None if candidate[4] is None and candidate[5] is None
                    else sha_blob(candidate[4], candidate[5]),
                ],
                # Never serialize the potentially sensitive free-form SQL error.
                "error_empty": reason == "",
                "interrupted_marker": reason == "daemon restarted before apply completed",
            }
        if active and (latest is None or latest["id"] != active[0][0] or
                       latest["phase"] != active[0][1] or not latest["active"]):
            refuse("active apply journal is not the latest candidate")
        generation_count, generation_ledger_sha = complete_generation_ledger(db)
        declaration_count, declaration_current, declaration_sha = complete_declaration_ledger(db)
        profile_states, profile_snapshots, profile_nodes, profile_sha = complete_profile_snapshot_ledger(db)
        overlay_count, overlay_sha = complete_profile_overlay_ledger(db)
        source_count, source_sha = complete_profile_source_ledger(db)
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
            "generation_record_count": generation_count,
            "generation_ledger_sha256": generation_ledger_sha,
            "declaration_record_count": declaration_count,
            "declaration_current_revision": declaration_current,
            "declaration_ledger_sha256": declaration_sha,
            "profile_state_record_count": profile_states,
            "profile_snapshot_record_count": profile_snapshots,
            "profile_snapshot_node_count": profile_nodes,
            "profile_snapshot_ledger_sha256": profile_sha,
            "profile_overlay_record_count": overlay_count,
            "profile_overlay_ledger_sha256": overlay_sha,
            "profile_source_record_count": source_count,
            "profile_source_ledger_sha256": source_sha,
            "core_desired_state": core,
            "routing_mode": mode,
            "private_direct": bool(private_direct),
            "selection_revision": selected_revision,
            "selection_sha256": None if selected_raw is None else hashlib.sha256(selected_raw).hexdigest(),
            "recovery_required": bool(required),
            "active_apply_attempt": None if not active else list(active[0]),
            "prepared_inert_restore_count": pending,
            "inert_restore_record_count": inert_count,
            "inert_restore_ledger_sha256": inert_ledger_sha,
            "apply_journal_count": journal_count,
            "latest_apply": latest,
            "apply_history_count": history_count,
            "last_archived_apply": latest_history,
            "apply_history_ledger_sha256": history_sha,
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
    if (args.case not in vm.CASES or not vm.NONCE_RE.fullmatch(args.nonce) or
            not vm.DOMAIN_RE.fullmatch(args.domain) or not vm.UUID_RE.fullmatch(args.uuid)):
        refuse("unsupported disposable VM identity, checkpoint or nonce")
    expected_ack = "GUEST_AUDIT:" + args.domain + ":" + args.uuid + ":" + args.case + ":" + args.nonce
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


def write_private_baseline(dfd: int, name: str, report: dict) -> str:
    if not re.fullmatch(r"baseline-[0-9a-f]{32}\.json", name):
        refuse("invalid baseline filename")
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAX_WITNESS:
        refuse("baseline exceeded audit limit")
    fd = os.open(name,
                 os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(raw)
            f.flush()
            os.fsync(fd)
        os.fsync(dfd)
    finally:
        os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def inspect(args: argparse.Namespace) -> dict:
    witness, db_path = strict_args(args)
    with ExitStack() as stack:
        dfd = private_fd(witness, 0, directory=True)
        stack.callback(os.close, dfd)
        marker_sha = private_phase_marker_at(dfd, args)
        state = observe_db(db_path)
        baseline_name = "baseline-" + args.nonce + ".json"
        base_doc = {"format": VERSION, "case": args.case, "nonce": args.nonce,
                    "domain": args.domain, "domain_uuid": args.uuid,
                    "phase_marker_sha256": marker_sha, "state": state}
        if args.mode == "capture":
            digest = write_private_baseline(dfd, baseline_name, base_doc)
            if not file_identity(dfd, witness):
                refuse("witness directory changed after baseline creation")
            return {"status": "baseline_captured_no_reboot_claim", "baseline_sha256": digest,
                    "physical_power_loss_verified": False, "restore_authorized": False,
                    "metadata_deletion_authorized": False}
        if not SHA.fullmatch(args.baseline_sha256 or ""):
            refuse("expected offline-pinned baseline SHA-256 missing")
        baseline, baseline_hash = private_json_at(dfd, baseline_name)
        if (baseline_hash != args.baseline_sha256 or baseline.get("format") != VERSION or
                (baseline.get("case"), baseline.get("nonce"), baseline.get("domain"),
                 baseline.get("domain_uuid")) !=
                (args.case, args.nonce, args.domain, args.uuid) or
                baseline.get("phase_marker_sha256") != marker_sha):
            refuse("baseline changed, invalid or not bound to this experiment")
        host_chain = host_stop_chain_at(dfd, args, marker_sha)
        poststart_sha = host_poststart_at(dfd, args, marker_sha,
                                         args.baseline_sha256, host_chain)
        if not file_identity(dfd, witness):
            refuse("private lab witness directory replaced")
        if args.mode == "reconcile-verify":
            if args.case != "T15-prepared-journal":
                refuse("only the test-only T15 prepared phase may be reconciled")
            check_prepared_reconciliation(baseline.get("state"), state)
            if (private_phase_marker_at(dfd, args) != marker_sha or
                    host_stop_chain_at(dfd, args, marker_sha) != host_chain or
                    host_poststart_at(dfd, args, marker_sha,
                                      args.baseline_sha256, host_chain) != poststart_sha):
                refuse("host stop/restart receipts changed during guest audit")
            return {"status": "prepared_journal_sqlite_subset_manual_review_only",
                    "sqlite_subset_checked": True,
                    "prepared_journal_transition_checked": True,
                    "virtual_stop_witness_seen": True,
                    "host_stop_chain_checked": True,
                    "host_running_observation_checked": True,
                    "guest_reboot_verified": False,
                    "physical_power_loss_verified": False,
                    "core_health_verified": False,
                    "archive_hmac_verified": False,
                    "restore_authorized": False,
                    "metadata_deletion_authorized": False}
        if baseline.get("state") != state:
            refuse("guest post-boot SQLite snapshot differs from trusted baseline")
        if state["recovery_required"] or state["active_apply_attempt"] is not None:
            refuse("unfinished apply recovery remains; manual incident review required")
        if (private_phase_marker_at(dfd, args) != marker_sha or
                host_stop_chain_at(dfd, args, marker_sha) != host_chain or
                host_poststart_at(dfd, args, marker_sha,
                                  args.baseline_sha256, host_chain) != poststart_sha):
            refuse("host stop/restart receipts changed during guest audit")
        return {"status": "sqlite_subset_consistent_manual_review_only",
                "sqlite_subset_checked": True,
                "virtual_stop_witness_seen": True,
                "host_stop_chain_checked": True,
                    "host_running_observation_checked": True,
                "guest_reboot_verified": False,
                "physical_power_loss_verified": False,
                "core_health_verified": False,
                "archive_hmac_verified": False,
                "restore_authorized": False,
                "metadata_deletion_authorized": False}



def check_prepared_reconciliation(before: dict, after: dict) -> None:
    """A narrow read-only comparison; not a crash/reboot or restore verdict."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        refuse("missing before/after SQLite state")
    initial = before.get("latest_apply")
    final = after.get("latest_apply")
    active = before.get("active_apply_attempt")
    applied = before.get("applied_generation_id")
    archived = before.get("last_archived_apply")
    digests = before.get("applied_and_lkg_sha256")
    if (before.get("schema_version") != 18 or
            before.get("apply_journal_count") != 1 or
            before.get("apply_history_count") != 1 or
            not isinstance(archived, dict) or
            type(archived.get("id")) is not int or archived["id"] <= 0 or
            archived.get("phase") != "committed" or
            archived.get("generation_id") != applied or
            archived.get("target_revision") != before.get("config_revision") or
            not isinstance(digests, list) or len(digests) != 2 or
            digests[0] != digests[1] or
            archived.get("digests") != digests[0] or
            not isinstance(initial, dict) or not isinstance(final, dict) or
            not isinstance(active, list) or len(active) != 2 or
            active != [initial.get("id"), "prepared"] or
            type(initial.get("id")) is not int or
            archived["id"] >= initial["id"] or
            initial.get("phase") != "prepared" or initial.get("active") is not True or
            initial.get("error_empty") is not True or
            initial.get("interrupted_marker") is not False or
            before.get("recovery_required") is not False or
            type(applied) is not int or applied <= 0 or
            before.get("lkg_generation_id") != applied or
            type(before.get("config_revision")) is not int or
            before.get("config_revision") < 0 or
            initial.get("previous_generation_id") != applied or
            initial.get("generation_id") == applied or
            initial.get("base_revision") != before.get("config_revision") or
            initial.get("target_revision") != before.get("config_revision") + 1):
        refuse("baseline is not the single disposable T15 prepared checkpoint")
    expected = dict(initial)
    expected.update(phase="interrupted", active=False,
                    error_empty=False, interrupted_marker=True)
    if (final != expected or after.get("active_apply_attempt") is not None or
            after.get("recovery_required") is not False):
        refuse("prepared journal did not become only the expected interrupted record")
    immutable_before = dict(before)
    immutable_after = dict(after)
    for entry in (immutable_before, immutable_after):
        entry.pop("active_apply_attempt", None)
        entry.pop("latest_apply", None)
    if immutable_before != immutable_after:
        refuse("confirmed SQLite state changed beyond allowed prepared recovery")

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("capture", "verify", "reconcile-verify"))
    parser.add_argument("--case", required=True, choices=vm.CASES)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--uuid", required=True)
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
