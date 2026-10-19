# ADR 0134 — Complete bounded archived-apply ledger in disposable guest replay

- **Status:** M4 independent, read-only experimental audit. No T15/T23 acceptance, actual VM stop, host electrical power-loss or production restoration is provided.
- **Depends on:** ADR 0129–0133, including the real Go v18 `PruneRetention` / `apply_history` schema and non-authorizing Python guest replay.
- **Preserves:** Linux ordinary user, no TUN, original CN 28 groups, Custom → GeoSite → GeoIP → ACL → FINAL and no subscription/ISP route layer.

## Gap

ADR 0132 corrected the real v18 archive-retention contract by inspecting the latest archived row and comparing it with Applied/LKG. But unchanged current revision, archive **row count**, and most recent archived digest do not detect drift in an older terminal journal row, archived error message or archived timestamps. Such drift can be material to manually reviewing crash-and-recovery history even when current traffic and current SQLite generation appear sound.

## Decision

1. Advance guest-only baseline `format` from **2 to 3**. Old pinned v2 baseline files never silently pass under v3. The operator must use a new nonce/guest fixture rather than overwriting an existing immutable baseline. These baseline versions are experimental *audit document* formats; SQLite schema remains real v18 without migration.
2. Inside the **same** WAL-aware SQLite `mode=ro` transaction, read at most **512** ordered terminal `apply_history` rows (request 513 and refuse if exceeded); require increasing positive IDs, positive generation, nonnegative base revision with exactly base+1 target revision, permitted terminal phases, lowercase SHA-256 digests and safe owner-bounded error/timestamp representations. The query truncates potentially hostile error strings before transferring them to Python and refuses more than 4,096 UTF-8 error bytes or missing/oversized timestamps.
3. Calculate a deterministic SHA-256 over canonical ordered JSON field arrays including every archived ID/reference/revision/phase/digest, the *unprinted* error and all four archived timestamps. Return only **`apply_history_count`**, `last_archived_apply` (as before) and **`apply_history_ledger_sha256`**. Neither errors, raw config BLOBs, URLs, paths, credentials nor private timestamps leave the read-only report. The complete before/after subset comparison and prepared→interrupted narrowed comparison must keep the archived-ledger digest identical; only the permitted *active* journal transition can differ.
4. This hash does **not** independently authenticate old archived entries or reconstruct pruned generation BLOBs. A malicious change *before* an externally SHA-pinned baseline may be accepted as baseline data; collision resistance is not a historical HMAC or secret-bound authorization. Oversize historical state refuses rather than attempting unbounded inspection.
5. Align synthetic Python tests with actual v18 archive columns and timestamps. Require multirow success with unchanged DB bytes; reject changed **older** archived error with latest record, count, Applied/LKG and hashes untouched; refuse malformed old row, over-512 rows and overlong error. Add a separate real Go v18 cross-language test that creates multiple successful generations, captures and verifies an actual archived-history baseline, mutates only the *oldest* archived terminal row in disposable test SQLite, and confirms the actual Python guest auditor refuses.

## Remaining gates

The ledger covers only the archived *journal metadata*. It is not an authenticated encrypted archive, original vs detached signed-reclaim HMAC, content-addressed rule-inode closure, Core health/traffic observation, credible VM reboot or hardware power-fault proof. No Core activation, TUN, file reclamation, metadata deletion, auto-retry, recovery clearance, credentials import or user backup restore is enabled. T15/T23/T25 and the M4/M5 release matrix remain open; stable `main` stays untouched.
