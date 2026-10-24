# ADR 0106 — Rollback-only SQLite write-intent CAS for encrypted restore inspection

- Status: **M4 internal-only atomic-CAS prerequisite; non-activating, never restorable**.
- Builds on ADR 0086, ADR 0101–0105 and `docs/plan.md` T15/T23.
- Linux unprivileged, no TUN. CN 28 groups, Custom → GeoSite → GeoIP → ACL → FINAL, and no subscription/ISP routing layer are unchanged.

## Decision: atomic writer reservation, not a restore commit

The read-only `InertRestoreFence` from ADR 0105 is optimistic: while an authenticated candidate is being verified, live selection, declarations, routing mode or applied generation may change. A genuine future restore will need to compare every live binding **under the same SQLite writer transaction** as durable import preparation. This ADR implements the prerequisite without allowing any restore writing.

`storage.CheckInertRestoreWriteCAS(ctx, expectedFence)` uses the **same private SQLite store** as the active daemon. It begins an ordinary SQLite transaction, then executes a conditioned `UPDATE daemon_state SET config_revision=config_revision` whose predicates match the expected config revision, applied/LKG IDs, core desired state, routing mode, private-direct flag, current declaration revision/hash and selection revision, and require `recovery_required=0` and zero active apply journal slots. The guarded UPDATE establishes SQLite's single-writer reservation (including in WAL mode) but does not change a value. A mismatch must affect zero rows and is refused.

While the write reservation is still held, it reuses the **same complete** `readInertRestoreFenceTx` implementation as the read-only ADR 0105 path. This checks the selection JSON digest (not just its revision), the current declaration's actual document hash, and all applied/LKG generation config/manifest/source-map bytes, in one transaction. Only full fieldwise equality is accepted. The operation is bounded (4-second deadline), never calls the core, and performs an explicit **checked ROLLBACK** before reporting a successful *check*. Every error path defers rollback. There is no `COMMIT`, no archive/plaintext DB import, no new `generations` record, and no `prepared`/active journal slot.

`backupclosure.CheckInertRestoreWriteBoundary` first rechecks the held encrypted candidate and expected dry-run evidence (two complete HMAC/resource/SQLite/DDL/profile authentications, per ADR 0105). It then invokes the transaction-local write-intent CAS on the pinned live baseline. It accepts only a previously validated internal `InertRestoreDryRun`; a forged `RestoreReady=true`, stale digest or state change is refused. Its return value is **only an error**, never an activation or restore token.

## Failure injection and rollback guarantees

The following boundaries have tests:

1. **Before acquiring the writer reservation:** mutate current selection, declaration, routing mode, core desired state or config revision. The atomic predicate or full fence rejects the stale baseline.
2. **After acquiring writer reservation but before rollback:** inject a synchronous error or cancel context. Deferred rollback releases the lock and leaves the applied/LKG state, success history and active attempt unchanged.
3. **Concurrent writers:** a separate SQLite connection attempts a selection write while the guarded transaction holds the writer slot. It cannot commit before rollback, but can commit afterwards; that new revision invalidates the prior fence.
4. **Process crash:** a child process is SIGKILLed while it owns an uncommitted write-intent transaction. SQLite releases the lock and rolls back its uncommitted work; the main process verifies SQLite remains healthy and an ordinary selection update still succeeds.
5. **After candidate verification but before SQL CAS:** a test injects a valid selection or declaration change, which must be refused instead of activating a stale archive.
6. **Real locked v2 core:** managed-core integration executes the non-activating write-boundary check on a genuine sealed approved-core candidate.

A successful check **does not hold a lock after return**; a concurrent application can legitimately change current state immediately afterwards. Advisory candidate directory `flock` protects cooperative openers only, not adversarial same-UID inode mutation. This ADR deliberately does not use a no-op CAS check to authorize data import.

## Deferred safety gates

An actual restore implementation must integrate this atomic predicate into the *same committed transaction* that prepares an isolated candidate; use the daemon's operation gate, restore-unique journal and crash-safe resource leases; bind a verified native configuration and exact DNS/rules to those leases; and implement `Check → Activate → Verify → Commit` plus tested rollback-of-rollback for every disk/core failure boundary. Nothing in this slice implements such a committed transaction, isolated SQL staging, schema migration, 64 MiB+ streaming DB import, or key custody. The existing 64 MiB SQLite inspection cap remains.

`RestoreSupported=false`, `RestoreReady=false` (every report) and all backup-restore HTTP/CLI/TUI entrypoints remain disabled. T15/T23, offline license/resource closure and 72-hour/7-day/30-day stability gates are still open. Do not describe ADR 0106 as a completed restorable backup feature.
