# ADR 0126 — Advisory cross-process write admission for retained audit evidence

- **Status:** M4 internal-only admission guard for two existing proof publishers. No automatic cleanup, restore/import, Core activation or public backup/restore/cleanup interface.
- Extends ADR 0121–0125; unchanged SQLite v18 journal, original sealed ciphertext, live state, CN 28 rule presets and Custom → GeoSite → GeoIP → ACL → FINAL routing. No TUN or subscription/ISP routing.
- Safety: a global directory `flock` serializes **cooperating** writers; this is not a general filesystem quota against users who ignore advisory locking or a completed on-disk retention policy.

## Motivation

ADR 0125 added a bounded **read-only** census of the historical off-scope signed attestation and full-proof mirror across the existing private SQLite directory. Both known publication paths were still solely fenced by their *own* encrypted candidate lease, permitting two distinct candidate archives to concurrently observe room for one more file and then both publish into the same parent directory. A background timer or unsupervised deletion would weaken the backup audit chain rather than remedy this cross-candidate TOCTOU.

## Decision

1. Both existing explicitly invoked internal writers — `AttestSealedDurableReclaim` (ADR 0121) and `MirrorSealedReclaimEvidence` (ADR 0122) — must acquire the **same** advisory Linux `flock(LOCK_EX|LOCK_NB)` on an independently opened descriptor of the **existing** state parent. Its path is derived solely from the live database, UID-owned private 0700, and already pinned via `O_NOFOLLOW` component verification. No state/lock file, journal migration, PID expiry, OS signal handler, maintenance daemon, or caller-selected pathname is introduced.
2. Keep the original encrypted candidate lease/mutex and explicit original key for both publication operations. The directory flock is **additional** cross-candidate serialization. Nonblocking lock failure is a hard refusal; never stall indefinitely behind another process that may be blocked on the live database or encrypted archive.
3. Under the directory lock, run two complete ADR 0125 bounded scans of the private parent. Refuse any unsafe/missing/replaced owner-private 0400 proof, malformed 64-char lowercase SHA filename suffix, extra hard link, symlink, public mode or over-budget directory. Neither matching basenames nor valid UID/mode are authentication of *other* archives' HMACs.
4. Admit exactly **one** new canonical attestation or mirror filename only if it is absent and a prospective file would stay at or below **4,096 total parent-directory entries**, **256 total matching proof files**, and **40 MiB total matching proof bytes**. Its exact payload length must separately fit ADR 0121's 2,048-byte or ADR 0122's 256-KiB per-file ceiling. These are fail-closed publication-admission bounds, not garbage-collection triggers or a promise of free physical blocks.
5. Keep the directory flock through the existing source proof scan, original archive/journal/live CAS checks, and the final `O_EXCL|O_NOFOLLOW` publication plus file fsync and parent-directory fsync. Rescan immediately before the exclusive open to detect a late change even from an uncooperative out-of-band process; fail closed if anything no longer matches admission snapshot.
6. After parent fsync, scan twice more, requiring exactly **one newly present matching file**, expected SHA/size/mode and unchanged original proof inode/contents. Then repeat the original HMAC/source-scope/live-CAS checks. On any post-file-fsync failure, return no success receipt and never unlink, repair or adopt a partial visible marker. A process SIGKILL releases the kernel flock, but does not itself demonstrate genuine power-loss durability.
7. **Do not change** the old `InspectReclaimEvidenceFootprint` report: `QuotaEnforced=false` continues to mean *its read operation* cannot enforce a global quota or confirm arbitrary filesystem writers followed the advisory lock. No review/receipt grants retention-policy approval, inode deletion, automatic GC, restored SQLite import, route publication or Core startup.
8. Competing processes are required to cooperate with directory flock; an out-of-band writer with sufficient filesystem privileges can disregard it and defeat any hard global quota. Repeated scans merely narrow that race, not establish a security boundary against such writers. A real durable global quota requires separate shared write architecture, producer registry, multi-volume/crash/fault replay and operator-approved retention policies.

## Verification

- Two independently opened directory handles: one writer's nonblocking lock excludes the second; releasing the first allows the second if its *different* target filename is still available. Duplicate filename remains blocked and cannot be overwritten.
- A late external matching file (without cooperating lock) between admission and the pre-openat check triggers refusal without publishing the pending target.
- Synthetic and actual directories exercise canonical lowercase digest naming, exact 256-file/4,096-entry/40-MiB prospective bounds and no partial marker after rejected admission.
- Original ADR 0121 and ADR 0122 publishers are tested with the same externally held state-parent lock. Both refuse while busy, then publish successfully after release; independent HMAC source audit and SQLite live generations remain unchanged.
- Preserve all ADR 0121–0125 wrong-key, symlink, hard-link, stale CAS, SIGKILL and cross-restart tests. Complete CI: format, Vet, ordinary tests, four Race shards and managed Core integration. Linux `flock` portability and actual T15/T23 power-loss replay remain separate gates.

## Still out of scope

No permanent retention quota enforcement for noncooperating writers, coordinated waiting queue, cron cleanup, source-scope metadata unlink/rmdir, old pending-orphan scavenging, real filesystem power-cut T15/T23, full credential SQLite recovery transaction, Core Check/Activate/Verify plus rollback-of-rollback, CN offline resource/license closure, and 72h/7d/30d soak. PR #1 stays Draft; stable `main` is untouched.
