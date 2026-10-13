# ADR 0108 — Journal-bound encrypted resource lease reacquisition (no activation)

- Status: **M4 internal-only identity/revalidation prerequisite**, not restore permission.
- Builds on ADR 0104–0107, using unchanged SQLite v18 (no migration).
- Linux ordinary user, no TUN; CN 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL remain untouched; subscription/ISP routing remains excluded.

## Scope and failure model

An inert v18 `prepared` record survives process death, but the Linux directory `flock` in ADR 0104 **does not survive**. A row ID, current-state digest, or a formerly authenticated ciphertext is insufficient to claim a recoverable resource after restart.

This ADR introduces `backupclosure.AcquireInertRestoreResourceLease(ctx, liveStore, privateParent, recordID, key)` and `InertRestoreResourceLease.Revalidate(ctx, key)`. The caller must explicitly specify the record and a pre-existing private, UID-owned parent directory; the code does not select arbitrary candidates, auto-import them, or enumerate an external tree. The acquisition sequence is:

1. Read the **bounded v18 inert journal**. Require exactly one `prepared` row, the requested positive row ID, a validated single-component candidate scope name, and unconditionally false `RestoreSupported` / `RestoreReady`. No raw credentials, encryption key, absolute candidate path or historical plaintext is read from this row.
2. Reopen the **specific ciphertext candidate** via its existing safe, symlink-resistant private-directory/parent scans, reacquire the Linux exclusive directory `flock`, and perform fresh HMAC, per-resource hash, in-memory SQLite/schema/profile domain authentication using the explicitly re-supplied 32-byte key.
3. Retain the live lock and capture the regular single-link 0600 ciphertext **inode identity** for this single process lease. A second cooperating process cannot reacquire that directory while the lease is alive; `Close` and SIGKILL release the flock while leaving the ciphertext and journal on disk.
4. Re-run complete candidate authentication, compare ciphertext SHA-256, inventory SHA-256 and length to the journal row, then run an **atomic rollback-only SQLite writer-CAS** that checks the entire row identity (row ID, scope, both hashes, size, baseline, phase, timestamps) together with the current committed generation/LKG/selection/declaration/core/routing fence. Compare the ciphertext inode and metadata again afterwards.

`storage.CheckInertRestoreRecordCAS` performs the new transaction-local check: the ADR 0106 guarded no-change `UPDATE` first acquires SQLite's writer reservation and verifies the full content-hashed live baseline. The same transaction selects the bound pending journal row, checks canonical digest-bound contents, requires exactly one pending record, and compares all persisted fields and timestamps. It then **ROLLBACKs**. The result is never a write receipt or a durable reservation.

The earlier `RevalidateInertRestoreCandidateRecord` now uses this atomic journal+live CAS instead of independent final optimistic reads. It still never grants a restore privilege.

## Boundaries

The immutable inode identity is meaningful **only within this live process lease**. It detects replacement by an equal-byte new inode or altered metadata while the lease remains open, even though mere HMAC authentication would accept a byte-identical replacement. The inode is *not persisted*; a restart requires a new authenticated lease with a new inode identity. This is a deliberate trust distinction, not a cross-reboot kernel-lock guarantee.

The directory `flock` protects cooperative same-UID processes, not arbitrary malicious same-UID writers (who can alter file bytes or rename entries). Linux advisory locks and SQLite transactions cannot be combined into one durable cross-filesystem atomic commit. An adverse write can still happen immediately after the last check; a future real restore must repeat its own locked resource validation, daemon-wide operation gate and SQL CAS in the actual committed import transaction. Nothing here creates such an operation.

The lease exposes no candidate deletion or automatic abandonment method. **Disposal remains explicit and separate:** ADR 0107 `AbandonInertRestoreRecord` transitions the journal row; ADR 0104 `Discard` can separately remove a known private ciphertext, after independently obtaining its exclusive directory lock. A failed revalidation never prunes ciphertext or silently marks a row abandoned. This avoids an unsafe delete-before-commit ordering.

## Evidence / failure injection

Storage tests cover repeated rollback-only journal CAS without changing the live applied/LKG state, refused abandoned/changed/forged journal rows, configuration changes, injected errors, cancellations, and a second SQLite connection attempting to abandon a journal while a CAS writer lock is held.

Linux tests cover cross-process exclusive leases, SIGKILL and re-acquisition with fresh key-based authentication, incorrect key, live selection drift, explicit abandonment, unknown candidate-directory siblings, and **same-byte ciphertext replacement with a new inode**. Managed-core integration exercises a real approved, sealed sing-box v2 candidate through the journal-bound acquisition and revalidation path without launching or switching the core.

The SQL schema remains **v18**. Old sealed v17 archives continue strict read-only inspection, and v18 archives with active pending inert logs still fail closed. There are no new network endpoints or privileged capabilities.

## Remaining gates

This is not a persistent executable-core/rule-set resource pin, isolated SQL import, restorable database staging, transactional activation or dual rollback. The 64 MiB bounded authenticated SQLite preflight, T15/T23 full power-loss transition tests, and 72h/7d/30d long-run gates remain open. Both `RestoreSupported=false` and `RestoreReady=false` are unconditional; no CLI, TUI or HTTP restore feature is enabled.
