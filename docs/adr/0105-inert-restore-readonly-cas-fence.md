# ADR 0105 — Read-only transactional restore CAS fence and fault-injected dry run

- Status: **M4 internal-only isolation/fault-injection prerequisite**. No restore preparation journal, SQL import, core activation, or public endpoint.
- Builds on ADR 0086 and ADR 0094–0104; `docs/plan.md` T15/T23 are NOT satisfied.
- Linux ordinary user, no TUN; CN 28 groups, Custom → GeoSite → GeoIP → ACL → FINAL; subscription/ISP routing excluded.

## Why a read-only fence first

A persistent encrypted candidate (ADR 0104) survives a process crash but holds **no durable activation lease** between processes. Even an authenticated candidate must never be coupled with a stale snapshot of the currently applied configuration, current selection or declaration. The write-capable `PrepareHistoricalRestore` in ADR 0086 is specifically for a retained historical generation, NOT an encrypted backup; reusing it here would incorrectly create an active prepared attempt before backup resources and rollback-of-rollback are implemented.

Introduce `storage.ReadInertRestoreFence(ctx)`: one SQLite **read transaction** binds the committed configuration revision, applied generation and LKG IDs, current declaration revision plus digest, current selection revision plus SHA-256 of its bounded JSON, routing mode, private-direct flag and desired core state. Both currently applied and LKG generation config/manifest/source-map blobs and the current declaration body are hashed afresh against their stored SHA-256 fields before the fence may be returned. Only exact, valid state with no `recovery_required` flag and no active apply journal slot is accepted. The fence is a comparable **digest-only/ID-only**, nonsecret value; no private config JSON, subscription URL or credentials leave storage. The read transaction rolls back (read-only) and does not create a new `prepared` generation.

`storage.RecheckInertRestoreFence` re-reads the same source and compares every field. It is an **optimistic read-only comparison**, *not* a SQL compare-and-swap write, resource lease, serialized daemon operation gate or durable commit receipt.

## Candidate-bound dry-run phases

`backupclosure.InspectInertRestoreDryRun(ctx, store, lockedCandidate, key)` performs:

1. An atomic SQLite read-only fence on the current live store.
2. A complete candidate `Verify` with a live exclusive candidate directory flock, including HMAC, resource hashes, in-memory SQLite integrity, DDL and profile audit.
3. Another complete candidate `Verify` to detect a changed ciphertext between checks.
4. A fresh transactionally read live fence that must exactly match the initial one.

Any rejected step yields an **empty report** with a generic error. `RecheckInertRestoreDryRun` repeats this work and requires equality to a caller's prior dry-run evidence; a forged `restore_ready`, changed ciphertext hash or stale live binding is refused. The report always has `RestoreSupported=false` and `RestoreReady=false`, even for an approved local-architecture v2 core.

The read phase DOES NOT hold an SQLite write lock while verifying the encrypted archive, avoiding an unbounded write outage. As a consequence, another valid writer can still change the state immediately after the final read. The returned report **is not an authorization or atomic CAS**. A future implementation must acquire the real daemon operation gate and use a fresh database-local CAS and durable resource pinning immediately before modifying anything.

## Fault injection and remaining release gates

Tests inject deterministic failures or cancellation after the initial fence and between candidate verification passes; they mutate the live selection/declaration under the inspection, corrupt the ciphertext after a successful first verification, and exercise active apply and `recovery_required` refusal. Tests also verify unchanged live applied/LKG state, no apply journal insertion, no core activation, and no plaintext candidate extraction. Managed-core CI tests the dry run with a real locked sing-box v2 candidate; even that path remains non-restorable.

This is **not** a transactional backup restore and does not implement rollback-of-rollback, crash-safe cross-restart resource generations, a durable activation lease, migration, atomic import or T15/T23 power-loss tests. Future steps must implement a safely isolated write staging area, pre-commit locks, exact resource binding, a recoverable apply journal and fault injection at each actual activation/rollback transition. Encrypted archive key custody and the 64 MiB in-memory SQLite audit cap remain unchanged. No HTTP/CLI/TUI route is added.
