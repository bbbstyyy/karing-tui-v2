# ADR 0111 — Memory-only, journal-bound portable rule-path relocation preview

- Status: **M4 internal-only proof**, not an archive importer, user command, or activation operation.
- Preconditions: ADR 0102/0103 authenticated SQLite/schema/profile preflight, ADR 0108 exclusive pending-journal ciphertext lease, ADR 0110 ephemeral resource probe.
- SQLite schema remains v18. Linux user process, no TUN; CN original 28 groups and Custom → GeoSite → GeoIP → ACL → FINAL, without subscription/ISP routing.

## Problem

The historical native sing-box config and its compiler-owned `NativeManifest` persist absolute rule-set paths below the original Linux XDG state root. Even an authenticated and anonymous-materializable encrypted snapshot is **not portable**: replaying native bytes unchanged against another state directory would use nonexistent paths or accidentally reference existing untrusted resources. A real restore must rebind these paths without changing routing intent, native tags, DNS, outbounds, selection, credentials, or historical source bytes.

ADR 0110 shows rule and approved-core payloads can be physically materialized into short-lived unlinked `O_TMPFILE` inodes, but deliberately returns no usable pathname or executable. ADR 0111 provides the separate **read-only relocation proof** needed before designing any durable file import.

## Decision

Introduce `InertRestoreResourceLease.PreviewPortableRulePaths(ctx, targetStateRoot, key)`, returning only a bounded, nonsecret `InertPortablePathPreview` digest/count report. No rewritten JSON, target path, source path, node/proxy data, file descriptor or recovered credential is exposed. Both `RestoreSupported=false` and `RestoreReady=false` remain unconditional.

1. Reject empty/relative/noncanonical and control-character target roots, the Linux root itself, and any target nested under the encrypted-candidate namespace. The target root is **hypothetical**: no directory is opened, stat-ed or created. This does *not* attest target ownership, available disk space, symlink safety, or durability.
2. Hold the same live in-process mutex and Linux encrypted-candidate directory `flock` for the entire preview. Reverify the full encrypted archive, immutable ciphertext inode, archived in-memory SQLite/schema/profile, exact pending v18 journal row, and current Applied/LKG/declaration/selection/core CAS before beginning.
3. Replay and hash the full ciphertext and deserialize only the authenticated, **at most 64 MiB**, credential-containing SQLite payload into a private `:memory:` database. Repeat independent integrity, DDL, domain and native manifest verification; use a **separate read-only SQLite connection** with `trusted_schema=OFF`, `temp_store=MEMORY` and `query_only=ON` to enumerate at most 32 generations.
4. For each retained generation, rehash the archived original config and manifest against the canonical encrypted inventory. Validate the strict compiler manifest/JSON local `route.rule_set` bindings. Refuse extra or duplicate tags, nonlocal rules, unexpected formats, missing resource inventory entries, altered SHA-256 or different original paths.
5. Map exactly each local rule binding to the lexical prospective path `<targetStateRoot>/core/rule-sets/sha256/<authenticated-SHA256>.json|.srs`. Do **not** touch route rules, DNS, inbounds/outbounds, other paths, node/selection data or the unchanged historical manifest. Compute a SHA-256 digest of the hypothetical reserialized native config and destroy that temporary byte buffer. A target equal to the historical state root is a no-op, keeping the original digest without unnecessary serialization.
6. Aggregate bounded original/manifest/rebound content digests into a deterministic SHA-256 preview. **Never return modified bytes**. Recheck the complete live journal/CAS and encrypted inode after all generations; reject any drift, cancellation or injected fault. A successful preview does not persist anything and is not a write-CAS commit permit.

The virtual rewritten JSON is not a core-checkable artifact or a replacement for the original compiler output; its digest is an audit hint only. Original stored generations, manifest/source-map SHA-256, live selection, DNS policy and routing remain untouched. Node/proxy secrets remain in transient SQLite/JSON memory; no decrypted credential SQLite file is created on disk.

## Verification

- Same candidate + same hypothetical root yields the same digest; a second target root produces a distinct bound digest when local rules exist. No target directory is created.
- The archived original config is unchanged. A separately reconstructed expected object confirms **only** `route.rule_set[].path` changed and confidential unrelated fields remain intact.
- A source-root no-op retains the original SHA. Mixed two-generation history (one rule-bearing, one rule-free) relocates only one generation.
- Reject malformed roots, wrong/zero keys, canceled context, nonmatching rule inventory or manifest, corrupt database bytes, in-flight selection changes, journal abandonment and even byte-identical cipher inode replacement.
- Concurrent `Close` cannot release the lease while previewing; no state/application/journal transition occurs.
- The real approved sing-box integration fixture executes this preview against an authenticated v2 archive without executing or loading the core.

## Remaining hard blockers

This is **not** a data import, migration to the current schema, filesystem validation, persistent resource lease, or recompiled/activated configuration. No same-transaction CAS with a real imported generation or journal state exists, and no Check/Activate/Verify/rollback-of-rollback/T15/T23 power-loss process has been proven. A future real recovery must recompile under the current trusted state/resource root, recheck native semantic equivalence, create inode-pinned durable resources with atomic commit/rollback, handle credentials and policy/proxy lifecycle safely, and validate directory safety at the moment of use. Also outstanding: complete offline CN rule bundle and licensing, remaining subscription formats, full TUI functions and 72h/7d/30d long-soak evidence. Keep PR #1 Draft and restore entrypoints disabled.
