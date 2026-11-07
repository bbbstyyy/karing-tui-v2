# ADR 0096 — Bounded snapshot-consistent rule resource closure (internal only)

- Status: M4 **non-restoring, non-exporting prerequisite**. No public backup, import, historical activation, or restore.
- Dependencies: ADR 0084–0095; `docs/plan.md` §§13.5, 18.3, M4.
- Scope: ordinary-user Linux, no TUN, retained CN presets, five routing layers without subscription/ISP routing.

## Problem and consistency boundary

SQLite `VACUUM INTO` preserves a coherent *database* view but by itself excludes external content-addressed `core/rule-sets/sha256` resources. Reading live generation references after snapshot creation risks mixing different database revisions. It is also unsafe to assume previously compiled native JSON implies that its local rule resources are still present.

The new internal-only `internal/backupclosure.Build` first obtains the WAL-consistent, flock-held SQLite snapshot from ADRs 0094–0095. All generation references and their config/manifest/source-map bytes are read **only from that immutable SQLite snapshot**, never separately from mutable live database state. This includes retained prepared/failed rows (not merely applied/LKG) because the database copy includes them. Up to 32 retained generation rows may be examined; overflow or a legacy generation without strict native manifest/declaration provenance fails closed.

Each generation requires exact size-bounded lowercase SHA-256 and JSON validation for the native config, compiler-owned manifest and source map, supported native schema and a verified immutable declaration revision/hash from the **same** copied SQLite database. The native `route.rule_set` local bindings must match the manifest one-for-one (type, format, tag, exact private path), with no omissions or extra entries. Rules must resolve solely under the known private state root's `core/rule-sets/sha256/<sha>.json|.srs` directory; directory ownership, permissions and symlink components are checked.

## Independent resource closure and manifest

The union is SHA/path deduplicated, sorted and capped at 128 distinct rule resources / 128 MiB in total. Each source file is opened with the existing no-follow `coreartifact.PinRuleSet` mechanism; its inode and SHA are verified, the link count must be one, and private independent read-only copies are produced by the existing bounded, flock-held `StagePinnedRuleSetSnapshot` mechanism. Source pins are reverified **after copying** to detect same-content inode swaps and in-place content changes. Independent copies are verified by their own hashes, inode and permissions; SQLite snapshot bytes/digest/quick_check are independently reverified before and after resource assembly.

A deterministic versioned `InventoryJSON` and SHA-256 digest bind: database file hash/length, storage schema, all retained generation IDs and config/manifest/source-map hashes, declaration revisions, and only the relative filenames, SHA-256, sizes and formats of every copied rule. They intentionally contain no raw configuration, subscription credentials, original absolute paths, control secrets or original rule bytes. The inventory declares `contains_credentials=true` conservatively and `restore_ready=false` categorically. The inventory exists **in memory only**; it is not an exported archive or a persisted recovery permit. No CLI/TUI/HTTP route or scheduled task invokes this path.

## Failure policy and tests

A strict 90-second total budget, 32/128 entry limits, 128 MiB rule budget, 128 KiB inventory limit, plus underlying 30-second / 768 MiB SQLite snapshot limit prevent unbounded successful work. Failures reject missing/modified/symlinked/hardlinked rule files, corrupted database copy, altered isolated copy, forged manifests, incomplete historical metadata, unlisted native rules and canceled operations. Successful and rejected paths close the independent copied resources and sensitive SQLite scope; no core activation or applied generation state is modified. A concurrent live declaration edit after the SQLite snapshot does not change the copied inventory.

## What remains open

This **does not bind the core binary**, install a durable cross-restart resource lease, reserve entire disk quota, create/encrypt/sign/publish a portable archive, or implement snapshot retention/restore and rollback-of-rollback. The isolated copies are destroyed at `Closure.Close`. The source inode pinning does not protect against a malicious same-UID actor capable of adversarial ABA mutation between checks. The current SQLite schema number and compiler native ID are explicit hard gates requiring review on upgrades. Backup/export, import/restore, M4 and M5 release gates all remain closed.
