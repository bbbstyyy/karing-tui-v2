# ADR 0122 — Bounded off-scope full-proof mirror for inactive terminal reclaim

- **Status:** M4 internal-only and non-destructive. No active Core/rule-set mutation, metadata deletion, backup restore, service integration, CLI/TUI/API, background GC, or operator cleanup permission.
- Extends ADR 0119–0121. SQLite v18, original encrypted archives, live declaration/selection and Core configurations are unchanged.
- Linux ordinary UID, no TUN. Retain CN 28 original presets, Custom → GeoSite → GeoIP → ACL → FINAL; subscription/ISP-derived rules remain excluded from runtime routing.

## Problem

ADR 0121 stores an independently signed external summary of completed private rule reclamation. Its SHA-256 bindings can *authenticate* the original plan/completion, but the summary alone does **not preserve their bytes** or every per-leaf deletion intent if their directory is later removed. Deleting the sole full signed audit history based only on those hashes would make crash recovery and operator forensic checks incomplete. This stage must preserve a **full bounded copy** before anyone designs a destructive terminal metadata retirement protocol.

## Decision

1. `InertRestoreResourceLease.MirrorSealedReclaimEvidence(ctx, key, expected)` is a **manual internal-only** step after successful ADR 0120 sealing and ADR 0121 external attestation. The expected attestation receipt is merely an optimistic expectation; independently re-open the original ciphertext lease, validate original 32-byte archive key, HMAC/ciphertext SHA and in-memory archived SQLite/schema/profile, exact still-prepared v18 journal and live Applied/LKG/declaration/selection/Core CAS, then the entire signed plan, completion and all signed per-rule intents.
2. Derive the mirror location **only** from the existing live database parent; require current-UID 0700 private directory through no-follow pinned parent descriptors. Its immutable basename is `.ktui-inert-reclaim-mirror-v1-<authenticated-ciphertext-sha>`. No caller-supplied pathname, archive-provided path, alternate volume or restore target can influence it.
3. Canonical JSON embeds the **original canonical plan, completion, independent external attestation and all exact, sorted three-digit per-leaf intent names and authenticated MAC values**. Bind archive/inventory SHA, plan/completion/attestation SHA, prepared journal ID, private reclaim-scope dev/inode, original rule count and unlinked bytes. Authenticate the entire canonical body with the same original archive key but a **separately domain-separated HMAC-SHA256** from the original plan, intent, completion and external attestation. The copy contains no deleted rule payload, executable Core, SQLite plaintext, credentials or active native config.
4. Bound the original inventory at 1–128 rules and the entire signed mirror to **256 KiB**. Refuse malformed, unexpected, symlink, hard-linked, executable, public or missing evidence, changed source file identities, changed external attestation, stale live CAS or canceled context. Check the original evidence and anchor at least twice before publication.
5. Exclusive `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` writes exactly one 0400, current-UID, single-linked private file; `fsync` its bytes and then its parent directory. Duplicate and partial/broken mirrors are **never** overwritten or repaired. On a fault after the file fsync but before the directory fsync, report **no success**. A visible marker may be independently checked, not auto-completed.
6. `InspectMirroredReclaimEvidence(ctx, key)` reacquires a still-prepared ciphertext lease after process restart and regenerates the expected signed mirror from *all original evidence*, authenticates both external anchor and mirror through descriptor-relative reads, and compares inode identity across two full independent scans with live CAS. Returns only bounded digests/counts and `MirrorRetained=true`, `OriginalProofsRetained=true`, `RequiresRevalidation=true`, `RestoreSupported=false`, `RestoreReady=false`. The mirror is **not** a durable inode pin and grants **zero** permission to unlink a plan, intent, completion, reclaim directory or its own file.
7. No automatic retry, TTL/PID garbage collection, `RemoveAll`, final `rmdir`, journal phase change, import, restore, Core Check/Activate/Verify or public backup/cleanup command is permitted in this ADR.

## Verification

- Golden test compares every mirrored embedded byte to the original signed plan/completion/attestation and per-rule MAC file, with no original/source/live-state mutation and no raw rule content.
- Wrong key, stale expectation, absent/altered anchor, missing intent, unknown scope entry, permission violation, late same-byte inode swap, selection/CAS change, closed/canceled lease, duplicate mirror, public/tampered/symlink mirror, and late error before/after publication all fail closed.
- Child process is SIGKILLed after mirror file `fsync` but before state-parent-directory `fsync`; a new lease reauthenticates *visible* evidence and confirms intact original source, journal and live generation. This is **not** a real power-loss durability test.
- Approved real-Core integration checks that mirroring the rules-only audit metadata leaves the current active rules and SQLite generation untouched. Full Go unit/race/build and managed-core CI are required before claiming this checkpoint passes.

## Release gates still blocked

Actual transfer of **verification authority independent of the original source scope**, operator-reviewed retention policy and final metadata destruction, old pending-orphan reclamation, genuine power-loss T15/T23, full credential-bearing SQLite import, target rules publication, Core Check/Activate/Verify with rollback-of-rollback, CN offline resource licensing, and 72-hour/7-day/30-day soak remain open. This ADR **deliberately does not** introduce the destructive protocol. PR #1 remains Draft.
