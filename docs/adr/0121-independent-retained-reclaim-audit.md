# ADR 0121 — Independent retained terminal reclaim audit anchor

- **Status:** M4 internal-only audit evidence. No metadata cleanup, restore/import, Core activation, API/CLI/TUI or automatic garbage collection.
- Extends ADR 0119–0120; SQLite v18, ciphertext archive format and live generation state remain unchanged.
- Linux ordinary UID, no TUN. Preserve CN 28 presets, Custom → GeoSite → GeoIP → ACL → FINAL, and the exclusion of subscription/ISP routing.

## Motivation

ADR 0120 authenticates terminal completion *inside* the inactive reclaim scope, with the original immutable HMAC plan and one HMAC intent per removed rule. The scoped evidence is intentionally not deleted. A future reviewed cleanup would require independent provenance outside that directory before even considering metadata retention, but an external digest alone cannot substitute for reauthentication of the original archive, journal and live state.

## Decision

1. `AttestSealedDurableReclaim(ctx, key, expected)` is an explicit internal-only operation on the original encrypted-candidate resource lease. Its expected ADR 0120 receipt is an optimistic fence only; the implementation independently authenticates the ciphertext, SQLite profile/schema, prepared v18 journal, live Applied/LKG/declaration/selection/Core CAS, original plan and every signed intent and completion marker.
2. Derive the attestation location **only** from the live database parent, which must already be a private current-UID 0700 directory. Reopen the path components using no-follow directory descriptors. Publish a single hidden `.ktui-inert-reclaim-attest-v1-<archive-sha>` private 0400 file in that directory, not inside the reclaim scope.
3. The canonical JSON payload binds archive SHA, inventory SHA, original plan SHA, completion-marker SHA, exact journal ID, reclaim scope device/inode, original rule count and total absent byte lengths. Authenticate via HMAC-SHA256 using the caller-provided original archive key and a dedicated domain string distinct from per-leaf intents and ADR 0120 completion.
4. Require `O_CREAT|O_EXCL|O_NOFOLLOW`, one-link current-UID private regular-file semantics, file fsync and parent-directory fsync. A preexisting file (including symlink, partial file or malformed marker) blocks a repeat writer; neither overwrite nor auto-repair is allowed. Revalidate complete original sealed evidence and live CAS before writing and again after.
5. `InspectRetainedReclaimAttestation(ctx, key)` is a separate read-only checker. Even after restart, it requires a newly acquired original ciphertext flock/lease, explicit key, exact live journal/CAS, **every** original signed proof still in the reclaim directory, and the canonical, private external attestation file. Repeat the evidence and inode reads; never infer authority from the file name or a previous receipt.
6. On error after file fsync but before parent-directory fsync, return no success receipt. A visible marker may be independently reauthenticated, but power-loss durability is not claimed without T15/T23 replays.
7. Returned reports have `AttestationRetained=true`, `OriginalEvidenceRetained=true`, `RequiresRevalidation=true`, `RestoreSupported=false`, `RestoreReady=false`. **The external marker does not permit any deletion**, including its own removal, original plan/intent/completion removal or final-directory `rmdir`. It is solely an additional immutable evidence boundary.

## Verification and unresolved gates

Tests cover successful one-rule terminal attestation, duplicate refusal, independent lease reacquisition, wrong key, mismatched expected plan, extra original-scope entry, source-proof disappearance, symlink/tamper/public attestation, canceled request and uncertain post-file-fsync publication. CI race/unit tests and managed-core integration remain the validation gate for this branch.

Still **blocked**: reviewed final metadata/tombstone retention and removal, crash-consistent old pending-orphan policy, actual power-loss test T15/T23, restored credential SQLite import, target rules publication, full Core Check/Activate/Verify and rollback-of-rollback, CN offline resource/license closure, and 72h/7d/30d soak. PR #1 remains Draft.

## Hardening: independent scans and process death

The read-only verifier now compares the actual **same inode identities** of the external 0400 attestation and **every** original signed proof across two full independent scans. Canonical bytes and correct HMAC are necessary but not sufficient if an entry has been swapped between scans. The crash fixture places a child process after private attestation file fsync and before the state-directory fsync, sends SIGKILL, then uses a freshly acquired ciphertext lease in the parent to authenticate the visible off-scope marker and all original proofs. Only visibility/re-authentication after process death is established; real filesystem power-loss durability and final metadata removal are **not** established.
