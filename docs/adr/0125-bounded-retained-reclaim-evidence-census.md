# ADR 0125 — Bounded read-only census of off-scope reclaim proofs

- **Status:** M4 internal-only forensic and resource-budget observation; **not** a cleanup, GC, retention-policy authorization, quota-enforcement or restore feature.
- Extends ADR 0121–0124; original ciphertext format, prepared SQLite v18 journal and Applied/LKG/Core state remain unchanged.
- Linux ordinary user, no TUN. Preserve CN 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL, excluding subscription/ISP-derived routing.

## Motivation

ADR 0121/0122 add one private immutable HMAC attestation and full-proof mirror per completed inactive-reclaim archive. Forensic artifacts can accumulate over many archives; ADR 0124 verifies one prepared archive but does not measure **global occupied proof-file space**, count unmatched external proof names or bound the work required to inspect the existing private state directory. Long-running systems must not pretend that a signed mirror is a deletion permit, nor silently ignore proof accumulation.

This stage is **strictly a bounded inventory**, not a retention decision: authenticating another archive's historical signatures is impossible without that archive's own original key and still-prepared journal. A pair of matching filenames alone is not a cryptographic relationship.

## Decision

1. Add internal `InertRestoreResourceLease.InspectReclaimEvidenceFootprint(ctx,key)`. It requires the original encrypted candidate's current flock lease, explicit original 32-byte key, a fresh `revalidateLocked` of ciphertext/journal/live Applied/LKG/declaration/selection/Core CAS, and a UID-owned private `0700` live SQLite parent derived *only* from the current store path. No caller path or filename accepted.
2. Reopen the existing state parent through pinned, no-follow directory descriptors and open a fresh descriptor-relative read-only `.` directory stream. Read at most **4,097 entries**, refusing rather than silently truncating if over the 4,096-entry review limit. Ignore unrelated SQLite/Core files, but consider **every** basename beginning with the two owned off-scope prefixes. Require a canonical lowercase exact 64-hex archive suffix; no extra path segments, noncanonical digest, unknown suffix shape or shadow form is accepted.
3. For every matching attestation/mirror, use `O_NOFOLLOW` and private single-link owner `0400` regular file checks, a descriptor-to-path inode identity fence and exact bounded read. The original per-file size limits remain **2,048 bytes** (attestation) and **256 KiB** (mirror). Refuse more than **256 proof files**, total matched proof bytes above **40 MiB**, unsafe permission, symlink, hard link, missing/changed file, or canceled context. These are **census work limits, not enforced writing quotas**.
4. Count total directory entries, attestation files, mirrors, suffix-matched *named* pairs and unpaired files, and bounded actual retained bytes. Do not expose any raw filename, absolute directory path, token, key, original rule content or HMAC. Pairing is deliberately based on basename suffix only and **does not authenticate** the content or establish correspondence to a valid prepared journal.
5. Independently re-open and scan the entire eligible entry set a second time under the same held candidate lease; compare exact file-name set, each content SHA-256, owner-private inode identity, total counts/bytes and state-directory identity, with live CAS refreshed before and after. A same-byte inode replacement or new orphan between scans fails closed. After return the report is only a point-in-time observation, not a durable inode pin or permission to act.
6. Always set `NamesOnly=true`, `CryptographicProofsVerified=false`, `QuotaEnforced=false`, `PhysicalCleanupAuthorized=false`, `RequiresManualReview=true`, `RequiresRevalidation=true`, `RestoreSupported=false` and `RestoreReady=false`. The existing ADR 0123 cryptographic inspector and ADR 0124 dual-boundary review remain separate and unchanged.
7. No on-disk mutation, lock-file creation, automatic GC, age/mtime-based expiry, rmdir/unlink, journal mutation, archive discard, SQLite import, Core execution or public backup/restore/cleanup API. If no valid lease/key exists for a historical archive, this method cannot reauthenticate that archive's HMAC history or classify it as safe to delete.

## Tests and acceptance

- Initially one independent attestation is counted as an **unpaired name**; after an ADR 0122 mirror, the same archive yields one named pair without claiming cryptographic proof or cleanup authority.
- Copy attestation bytes under another archive-shaped suffix: the copy increments the unpaired count but is *not* certified as a valid signed record. Refuse public, symlink or hardlinked matching names and same-content inode replacement between complete directory scans.
- Verify wrong key, canceled context, live selection CAS drift, fresh encrypted candidate lease after restart, and unchanged original SQLite generations and journal.
- A real approved Core integration should attest that this census does not touch current active rules, Core or the original reclaim source. Full unit, Race and real-Core CI remain mandatory; the prior ADR 0124 full four-shard Race gate must be independently observed before claiming it green.

## Next gates remain open

Enforcing *global* proof quotas across concurrent archive candidates needs a separate shared publication mutex and rollback/crash semantics; no write-side quota is introduced here. A reviewed operator retention policy and true durable final-metadata disposal, pending orphan handling, real T15/T23 power loss, credential SQLite restore, target Core Check/Activate/Verify and rollback-of-rollback, CN offline resource/legal closure and 72h/7d/30d soak remain uncompleted. **PR #1 stays Draft.**
