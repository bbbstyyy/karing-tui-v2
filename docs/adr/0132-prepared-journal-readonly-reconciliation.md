# ADR 0132 — Read-only T15 prepared → interrupted journal reconciliation (disposable only)

- **Status:** M4 test-only subset evidence. Neither T15 nor T23 is accepted; no actual guest shutdown, physical power loss, validated reboot, Core traffic, restoration or deletion occurs.
- **Prerequisites:** ADR 0128–0131. Work is isolated to the Python guest audit tool, Python unit mocks and Linux Go test fixtures. No production daemon/API/CLI/SQLite migration is added.
- **Invariant:** Linux ordinary UID, no TUN, CN 28 groups, five-layer Custom → GeoSite → GeoIP → ACL → FINAL routing, subscription/ISP route exclusion.

## Gap closed

The original `--mode verify` rightly refuses an active prepared journal, even after a correctly bounded `RecoverInterrupted` transition changes that row to `interrupted`. ADR 0131 tested only that refusal. There was no distinct, narrowly specified way to compare the original *externally SHA-pinned prepared* baseline with an actual after-reconciliation v18 Store snapshot, or prove the candidate generation did not change while the old Applied/LKG remained intact.

## Decision

1. Raise the guest auditor baseline document `format` to **2**. Former version-1 baselines fail closed. Add the last apply journal's ID, phase, active flag, base/target revisions, previous and candidate generation IDs, SHA-256 of its config/optional metadata BLOBs and redacted error-classification booleans. Record journal row count. Never export journal free-form error text, credentials or config contents. All reads remain in one WAL-aware `mode=ro` SQLite transaction.
2. Add `--mode reconcile-verify` **only for** `T15-prepared-journal`. Require the original pinned baseline SHA, identical private guest/host witness binding, exact fresh-v18 fixture shape (**two journal rows**), matching Applied/LKG and prepared attempt linkage, original empty error and unactivated candidate.
3. Accept exactly one candidate row transition `prepared, active=1, empty error` → `interrupted, active=NULL, standard RecoverInterrupted reason`. Require no other change to the inspected SQLite subset: migrations, desired Core/route state, declaration revision, Applied/LKG configs and metadata digests, selection revision/payload SHA, active independent restore count, journal count and candidate fields/digests are unchanged. Any extra/stale active attempt, altered target revision, candidate changes even with rehashed payload, changed selection or other phase must **refuse**.
4. Keep the old `--mode verify` strict: it still refuses a pre-cut prepared baseline after recovery because the snapshots are no longer equal. The new status is `prepared_journal_sqlite_subset_manual_review_only`; `guest_reboot_verified`, `physical_power_loss_verified`, `core_health_verified`, `archive_hmac_verified`, `restore_authorized` and `metadata_deletion_authorized` remain **false**. The host observation in CI is synthetic, not authentication of a real stop.
5. Python unit tests use synthetic disposable SQLite only. Linux Go cross-language regression creates real v18 Store Applied/LKG and pending prepared apply, calls the real Go `RecoverInterrupted` on that temporary DB alone, and requires the original Python guest auditor to prove only the narrow allowed transition. It verifies the read-only audit did not change the SQLite DB bytes and rejects subsequent Go selection drift.

## Boundaries remaining

The latest-journal/confirmed-generation subset **does not prove every historic row**, full rule-set inode closure, encrypted backup HMAC, VM/host boot identity, real Core health, physical durability, rollback-of-rollback or restoration. Never use this result to authorize original proof disposal, retention GC, history activation, recovery of user credentials, a public restore API or stable `main` release. Real independent T15/T23 fault-injection, complete rule and Core evidence, restore transaction review and 72h/7d/30d soak remain open.
