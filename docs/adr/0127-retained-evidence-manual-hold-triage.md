# ADR 0127 — Shared-lock manual hold triage for retained audit evidence

- **Status:** M4 internal-only, read-only, non-authorizing checkpoint. No retention-policy approval, physical metadata disposal, automatic GC, credential SQLite restore, Core activation or public API/CLI/TUI entrypoint.
- Extends ADR 0121–0126. SQLite schema v18, encrypted backup candidate format and live Applied/LKG/declaration/selection/Core remain unchanged.
- Linux ordinary user, no TUN. The original CN 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL five layers remain unchanged; never reintroduce subscription/ISP routing.

## Problem

After ADR 0126, the two cooperative HMAC audit-proof publishers share a bounded nonblocking directory `flock`, but an operator still has to reconcile three distinct kinds of evidence: (1) independently authenticated **historical** signatures for the current prepared archive, (2) a potentially missing/unverifiable **current original source-scope** audit, and (3) a bounded global **name/byte census** containing other archives' untrusted proof filenames. Confusing them can lead to accidental promises of safe deletion or quota enforcement. The current plan does not yet define an authorized retention period, durable tombstone, expiry procedure or physical power-loss evidence.

## Decision

1. Add `InertRestoreResourceLease.InspectRetainedEvidenceTriage(ctx,key)` as a **manual, internal, read-only** preflight. First perform ADR 0124's full retention review with the supplied original 32-byte archive key, encrypted candidate lease, complete original ciphertext and in-memory SQLite/schema/profile verification, exact still-prepared v18 journal, and unchanged Applied/LKG/declaration/selection/Core CAS. Require complete independently signed ADR 0121/0122/0123 history; if historical verification fails, return **zero report and error**, never a partial "unverifiable but safe" result.
2. Open only the **existing**, UID-owned 0700 private SQLite parent via ADR 0121 pinned `O_NOFOLLOW` descriptor checks. Acquire a **nonblocking shared** `flock(LOCK_SH|LOCK_NB)` on this directory. This blocks cooperating ADR 0126 exclusive proof publishers during the preflight, but it is advisory and cannot stop arbitrary out-of-band writers with filesystem access. A busy lock is an explicit refusal, not an unbounded wait or lockfile creation.
3. Under the shared lock, complete ADR 0125's owner-private 0400, single-linked, no-follow, bounded, twice-scanned global proof directory census. Require exact 4,096-entry / 256-proof / 40-MiB review bounds, canonical SHA names, internally consistent counts and the present archive's authenticated anchor+mirror (at least one suffix-matched pair). This census is **names and bytes only for other archives**. Never label an unfamiliar pair a valid signed history without that archive's original key/journal.
4. Re-run the entire current-archive cryptographic source/history retention review and the complete global footprint; compare both full reports exactly, and check private parent identity and cancellation before return. The two nested retention reviews are not a universal atomic filesystem snapshot; no returned inode or metadata is pinned past the call. A package-private seam verifies noncooperating same-content inode replacement and late CAS drift are rejected.
5. Return only an archive/mirror digest and bounded count/headroom figures: total directory entries, anchor/mirror/name pairs, unpaired names, retained bytes, free directory slots, free matching file slots, and arithmetic byte headroom. Classify **one prioritized manual-review reason**:
   - `original_source_unverifiable` if original signed scope cannot be fully reauthenticated, even while detached history is valid.
   - `unpaired_proof_names` when the name-only global audit finds a missing counterpart; never automatically repair/delete.
   - `bounded_admission_headroom_low` if the state parent lacks arithmetic room for two hypothetical **maximum-sized** future attestation/mirror payloads (2 directory slots, 2 proof slots, 2,048+262,144 bytes). This is not an OS free-space check, reservation, or permission for a writer.
   - Otherwise `retention_policy_unapproved`: a source-present and spacious state still **requires an explicit later operator policy**, review and real crash/power-loss evidence.
6. Every successful report forces `ManualHoldRequired=true`, `ForeignProofNamesOnly=true`, `AdvisoryLockHeldDuringReview=true`, `PolicyApproved=false`, `PowerLossReplayVerified=false`, `PhysicalCleanupAuthorized=false`, `RequiresRevalidation=true`, `RestoreSupported=false`, `RestoreReady=false`. No secret or original source path is returned. A failure returns no report.
7. Do not add age/mtime-based expiry, automatic retry, orphan adoption, final metadata unlink/rmdir, policy override flag, new journal schema, root permission, backup import, runtime rule publication or Core Check/Activate/Verify.

## Regression gates

- Real signed fixture: fully original authenticated source plus external attestation/mirror yields the manual-policy-needed condition, with no current SQLite/journal mutation.
- A foreign attestation-looking file reusing existing signed bytes but a different archive SHA name counts only as **unpaired**, not as a valid foreign signature. Moving the original source directory privately aside **without deleting it** makes `SourceStatus=unverifiable` while valid historical proof persists through new encrypted candidate lease/restart.
- A separate directory FD cannot take the ADR 0126 exclusive writer lock while a triage shared lock is held. A noncooperating same-byte inode swap between complete inspections is rejected; canceled context, wrong archive key and changed live CAS return zero.
- Pure policy arithmetic checks all exact capacity edges: 2-slot boundary, 2,048+262,144 worst-case pair byte boundary, unpaired/source priority, and impossible count relationships. No generated report grants cleanup/restore.
- Approved pinned real Core integration verifies current rules, SQLite and Core are unmodified. All format/Vet/unit/build, four full Race shards and managed Core integration must pass before merge.

## Remaining gates

This is not an operator-approved retention policy, hard global quota, final metadata deletion or real T15/T23 power-loss proof. A reviewed hold/retention schedule and audit export, durable tombstone and explicit crash-atomic final cleanup protocol, pending orphan reconciliation, full credential SQLite recovery, target rules installation, Core Check/Activate/Verify with rollback-of-rollback, CN offline licensing and 72h/7d/30d soak remain blocked. **PR #1 stays Draft; `main` is untouched.**
