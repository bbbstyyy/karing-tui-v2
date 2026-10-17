# ADR 0117 — Explicit, verified, non-destructive quarantine of inactive rule bundles

- Status: **M4 internal-only filesystem retirement precursor**, NOT deletion, restored execution, public cleanup or backup/restore readiness.
- Follows ADR 0107–0116. SQLite schema remains **v18**; no archive, journal, declaration, runtime core or active ruleset format changes.
- Ordinary-user Linux, no TUN; preserve CN 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL; subscription/ISP routing remains excluded.

## Motivation

ADR 0114 atomically published authenticated RULES ONLY into an isolated inactive `.ktui-inert-rules-v1-<ciphertext-sha>` directory. ADR 0115 can find but not trust stray scopes. ADR 0116 can reauthenticate an exact **complete** inactive rules bundle after restarting, but returns only an ephemeral read-only report. An orphan might be unwanted, but an unlink-based cleanup before a durable crash contract could erase an unrelated replacement file or leave a partly deleted completed-looking bundle.

The next deliberately narrow operation is **non-destructive quarantine** of one *complete, independently authenticated* inactive bundle. It never attempts to reclaim interrupted `.ktui-inert-rules-pending-*` directories whose ownership cannot be proved from a random directory name; unknown, already-retired or interrupted scopes remain blockers for explicit later review.

## Decision

Provide internal `InertRestoreResourceLease.QuarantineDormantRuleBundle(ctx, key, expected)`, with an `AuthenticatedDormantRuleReport` from ADR 0116 serving ONLY as an optimistic **expected digest/count**, not as permission to rename. The operation itself must independently verify everything again:

1. Require explicit invocation, supplied nonzero 32-byte archive key and full-shaped expected report: ciphertext/inventory digest, original published scope-name digest, count, total bytes and `RuleBytesVerified=true`, `Inactive=true`, `RequiresRevalidation=true`. Both permission flags must remain false. Wrong/forged/stale expectations, closed candidate lease and cancellation fail with a completely zero report.
2. Hold the live ADR 0108 candidate mutex and ciphertext-directory `flock`; revalidate the full sealed archive, archived SQLite/schema/profile, exact prepared v18 journal and unchanged Applied/LKG/declaration/selection/Core CAS. Reparse the independently authenticated original inventory with bounded 1–128 canonical rules, at most 128 MiB, and compare its exact ciphertext digest, inventory digest, count and total bytes to the expected evidence.
3. Derive the target solely from the authoritative state SQLite path: `<state-db-parent>/inert-rule-bundles`. Acquire the same existing UID-owned 0700 parent `flock` as ADR 0114. Accept only at most eight recognized completed (untrusted-looking) bundles and require the exact `.ktui-inert-rules-v1-<archive-sha>` entry. Reject ANY pending, unknown, symlink, hardlink, permissive, over-budget, added/replaced entry. Never operate on arbitrary caller-supplied paths.
4. Pin the exact source directory FD, separately re-read the *complete* file listing and hash every exact listed `<sha>.json|.srs` leaf through no-follow parent-relative FDs, checking size/SHA-256, owner, 0400 non-executable mode, inode, single hard link and total budget. Repeat directory entry/inode checks and source ciphertext/journal/live CAS **immediately before** committing. Any injected same-byte inode swap, changed bytes, late unknown/pending name, abandoned journal, changed selection or cancellation refuses the rename.
5. Commit **only one namespace operation**: Linux `renameat2(RENAME_NOREPLACE)` from the original published-looking basename to `.ktui-inert-rules-retired-v1-<archive-sha>` **inside the same private stage parent**. Destination collision cannot replace anything. Recheck the original basename is absent, the renamed directory FD identity and complete authenticated payload are unchanged; fsync the directory and its parent before reporting success.
6. An error **after** the rename (e.g., SIGKILL/parent fsync failure) has an *uncertain durability result*: never automatically rename back, overwrite, unlink or report successful retirement. The operator must inspect the private namespace separately. The retired basename is deliberately unrecognized by ADR 0114 staging and ADR 0115 ordinary audit: they fail closed instead of treating it as a reusable bundle.
7. Return only archive/inventory/retired scope-name SHA-256, rule count and bytes, `Quarantined=true`, `RequiresManualReview=true`, with `RestoreSupported=false` and `RestoreReady=false`. No source/destination paths, rule bytes, decrypted SQLite or Core executable FD ever escape. **The files still occupy disk, retain their original 0400 content and are not a trusted cross-restart lease.**

### Crash and threat contract

- **Before rename**: the original complete private scope remains unchanged and reusable only for a *new* read-only authentication; no destination exists.
- **After rename and before parent fsync**: the source entry has disappeared in the current process, but post-crash durability is uncertain. The dedicated `retired-v1` basename flags the result as non-reusable, even without a durable success receipt.
- **After fsync**: the old published-looking name is gone; the retained private rule bytes are non-activating. The completed retirement is an irreversible naming choice within this API; the caller cannot invoke a restore or deletion operation using the report.
- The parent `flock` serializes cooperating publishers and retirement calls, not arbitrary same-UID/root attackers. There is no Unix primitive here to guarantee protection from deliberately concurrent, same-UID malicious path replacement between two individual syscalls; require the dedicated private state directory and fail closed on observed drift.
- Because no data is unlinked, the result cannot be called free-space recovery or orphan **deletion**. Physical reclamation of exact, already-quarantined inodes (including restart/crash recovery) must be a separately reviewed, explicitly requested operation with its own durable intent and complete rollback/failure matrix.

### Validation

- Tests cover complete retirement without changing active rules, SQLite, current/LKG or the v18 journal; bytes remain present and private after all FDs close.
- Refuse forged/stale expected reports, wrong key, closed/cancelled context, late same-byte inode replacement, corrupt content, added/pending scopes, directory swap and live CAS/journal drift.
- Fault immediately after rename proves the error returns **no success receipt** and leaves data for manual review rather than automatic deletion or rollback. A forked Linux test process is SIGKILLed exactly at the post-rename hook; the parent observes retained private rules and unaffected live config, and can reacquire the original ciphertext but cannot automatically readopt the retired bundle.
- Managed approved Core integration authenticates and quarantines only rules after closing anonymous Core pins; no Core executable is persisted in the retired namespace or started.
- **Release gates still open:** explicit post-crash retirement inventory, authentic physical reclamation, durable resources, migration of credential-bearing SQLite, atomic restore write CAS/rollback-of-rollback, Core Check/Activate/Verify, real T15/T23 power-loss experiments, CN offline rule licensing and 72h/7d/30d soak. PR #1 remains Draft; no user-facing restore or cleanup command is introduced.
