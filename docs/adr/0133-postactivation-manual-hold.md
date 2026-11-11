# ADR 0133 — Postactivation and failed-rollback guest journal: persistent manual hold

- **Status:** M4 Linux test-only, non-authorizing fault-boundary regression; no T15/T23 acceptance or physical VM power-stop execution.
- **Dependency:** ADR 0130 real Go v18 test DB, ADR 0131 cross-language reader, ADR 0132 strict prepared→interrupted read-only comparison.
- **Constraints:** ordinary Linux UID, no TUN or privilege escalation, CN 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL unchanged, subscription/ISP routing excluded.

## Missing boundary

ADR 0132 deliberately accepts only an entirely **unactivated** `prepared` journal transitioning to `interrupted` with Applied/LKG preserved. A failure after a live Core might have been activated or might have been rolling back is substantially riskier: a matching old generation in SQLite is not evidence that the actual Core has rolled back. In particular, the original `RecoverInterrupted` sets a persistent `recovery_required` flag for **activating**, **verifying**, and **rolling_back** phases; repeat calls and restarts must never silently clear it.

## Decision

1. Add Linux Go-test-only `internal/storage/t15_postactivation_hold_linux_test.go`. Each stage creates a fresh owner-private disposable Go v18 SQLite database, commits an initial Applied/LKG, creates an unactivated second generation, and uses the actual Store methods to transition the second attempt to `activating`, `verifying`, or `rolling_back`. No daemon, Core, proxy socket, actual VM or signal is invoked.
2. Use the unchanged Python guest auditor to capture the real v18 pre-replay state and a **synthetic, non-authorizing host witness**, then require both ordinary exact `verify` and ADR 0132 `reconcile-verify` to refuse. A postactivation phase can **never** qualify as a safe `prepared` transition even when a fixture copies the matching VM ID and nonce.
3. Invoke the real Go `RecoverInterrupted` on that temporary DB. Require exactly one interrupted attempt and `NeedsReconcile=true`, preserved revision and Applied/LKG, unchanged candidate ID/config digest and Core desired STOPPED, and `RecoveryRequired=true` with no active journal. Repeat `RecoverInterrupted` and reopen the database; the persistent hold **must not** clear. Both Python verification modes must still refuse, and read-only auditing must leave the SQLite DB byte-identical.
4. Cover terminal `FailRollback` separately: it sets `RecoveryRequired=true` even with no active journal. Replaying with zero interrupted attempts must still retain the hold, never treat `failed` as a successful prepared reconciliation.
5. No programmatic `ResolveRecovery`, automatic Core restart, data migration, backup restoration, history import, rule-file rewriting or old evidence disposal is permitted here. All results remain **manual review only**, not boot, electrical power-loss, network health or authenticated archive proof.

## Still required for release

Actual T15/T23 needs independently witnessed guest power interruption/boot, exact Core process/route restoration, full encrypted backup and immutable rule-resource provenance, rollback-of-rollback, many other fault points and long-duration soak. This slice only guards the persistent SQLite state machine when the Core side may be uncertain. Outer PR #1 remains Draft; stable `main` unchanged.
