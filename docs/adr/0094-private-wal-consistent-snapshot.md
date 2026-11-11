# ADR 0094 — Private WAL-consistent SQLite snapshot foundation

- Status: **M4 internal-only backup prerequisite**; not a product backup, archive, export, import or restore.
- Environment: Linux ordinary-user operation, no TUN; existing CN five-layer routing and subscription/ISP exclusion unchanged.
- Related plan: §§13.5, 18.2–18.3, M4 and T15/T23.

## Decision and evidence boundary

A live SQLite database in WAL mode cannot be backed up by simply copying \`state.db\`: committed changes can remain in \`state.db-wal\`. Introduce \`storage.Store.CreateDatabaseSnapshot\` as an **internal-only** isolated copy mechanism. It uses the same configured SQLite connection and \`VACUUM main INTO ?\`, which SQLite documents as producing a consistent, transactional snapshot of the source (not an atomic backup of other files). The live source database, its WAL, and the applied core remain untouched. See https://sqlite.org/lang_vacuum.html and https://sqlite.org/backup.html. This is a self-contained SQLite file, not a substitute for the incremental online Backup API when larger snapshots or tight latency are required.

The caller passes an **existing** absolute private directory. The implementation rejects symlinked path components, an unsafe final owner or group/other access, and invalid size limits. It creates a random 0700 scope and exclusively pre-creates an empty 0600 \`state.db\` output; SQLite permits a pre-existing *empty* INTO destination. The process runs with a 30-second budget and a best-effort source page-count preflight against a 768 MiB cap, then enforces a strict actual output byte limit. No request may blindly copy a growing source file. After SQLite returns, the snapshot is checked for original destination inode, regular single-linked private file permissions, SQLite header, SHA-256 and a read-only immutable \`quick_check(1)\`. File and directory metadata is fsynced. \`DatabaseSnapshot.Close\` refuses unknown entries, hardlinks, inode replacement, changed permissions or non-private scopes rather than recursively deleting unrelated content.

Tests exercise committed WAL data, a subsequent live mutation that does not change the snapshot, source integrity, permissions and digest, strict budget, cancellation, symlink/loose directory rejection and tampered cleanup. Snapshot creation errors do not mutate an applied generation or enable restore.

## Unmet requirements / stop conditions

**This does not constitute a usable backup yet.** The isolated database contains profile credentials and does not include the external content-addressed rule resources, pinned core binary or complete inventory/manifest. No HTTP, CLI or TUI operation or automatic job calls this method. Its only supported use today is as a primitive for a future bounded, versioned encrypted/exportable backup flow.

The 30-second timeout and 768 MiB limit prevent *unbounded successful* copies but do not reserve disk space before SQLite writes, limit concurrent callers across processes, or implement orphan recovery after SIGKILL. A private scope created before an unclean exit may persist and contain secrets. Production use must first add snapshot parent ownership/locking, bounded orphan scavenging, resource-inventory snapshot consistency, backup metadata and format/secret warnings, durable packaging or encryption, and verified transactional restore with rollback-of-rollback. No failure to write a snapshot may interrupt an otherwise healthy proxy; no current daemon request invokes it. Full M4/T23/M5 gates remain open.
