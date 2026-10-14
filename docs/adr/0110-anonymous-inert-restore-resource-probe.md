# ADR 0110 — Anonymous, non-executable restore resource probe (internal only)

- Status: M4 prerequisite; **not** import, restoration, or a supported backup workflow.
- Builds on ADR 0104–0109. SQLite schema is unchanged at **v18**.
- Product scope remains ordinary-user Linux, no TUN; CN original 28 groups and Custom → GeoSite → GeoIP → ACL → FINAL; no subscription/ISP routing layer.

## Problem

ADR 0108 establishes an exclusively held ciphertext candidate and an inert, journal-bound CAS check. Its existing full HMAC/SHA, schema and SQLite inspection proved the encrypted resource bytes are authentic, but not that the local rule-set and pinned core bytes can be copied through a filesystem interface under bounded resource ownership. A future restore must not begin with a writable, named plaintext extraction directory or re-use a stale archive receipt from a previous process.

## Decision

Add `InertRestoreResourceLease.ProbeAnonymousResources(ctx, scratchParent, key)`, an **internal, synchronous, non-activating** operation. It takes an existing live ADR 0108 lease, the original caller-supplied 32-byte key, and a **separate, existing**, current-UID-owned 0700 scratch directory. The source remains the persistently encrypted candidate and is never modified.

While holding one `InertRestoreResourceLease.mu` through the whole operation:

1. Revalidate the candidate inode, full encrypted archive / in-memory SQLite and the exact pending SQLite journal row against current Applied/LKG/declaration/selection/core state.
2. Verify the scratch directory with a non-follow, pinned directory FD. Refuse unsafe modes, symlinks, candidate reuse and missing/unsupported filesystem primitives.
3. Re-authenticate the **whole** ciphertext SHA before parsing the small canonical inventory; the canonical resource sizes and SHA digests remain bound to the journal.
4. Stream the archive again through AES-CTR, SHA-256 and HMAC-SHA-256. Hash the SQLite payload directly into discard (**no plaintext SQLite file**). For each rule file and the optional approved core, open one Linux `O_TMPFILE|O_CLOEXEC` relative to the verified directory FD. Its only file descriptor starts owner-only 0600, must have link count zero, is rehashed against the canonical resource digest, chmod 0400 (non-executable), fsynced, read back/rehash checked and **closed before the next file**. At no point is a pathname, plaintext buffer or resource FD returned to the caller.
5. Verify the archive's final MAC, full ciphertext SHA, source inode/size/mode/mtime, directory inode and context deadline. Revalidate the original journal/target CAS again **before returning**. Any fault yields an all-zero report; no retry or restoration is attempted.

The only output contains safe archive hashes, resource counts/sizes and `AnonymousFilesChecked`. `RestoreSupported=false` and `RestoreReady=false` are unconditional. A change during the probe, a canceled request, unknown symlink, wrong key, changed pending journal, or scratch directory inode replacement fails closed.

## Resource and threat boundaries

- **No named plaintext files** are created, so an ordinary process crash, SIGKILL or successful return drops the temporary descriptor automatically. `O_TMPFILE` is mandatory; filesystem incompatibility is an explicit refusal, never a fallback to a named file.
- The resource payload budget is inherited from the authenticated closure inventory: at most 128 rule sets / 128 MiB total plus one approved core of at most 256 MiB; one descriptor/resource is live at a time. Disk free-space reserve is checked before streaming. Authentication still follows the existing 64 MiB SQLite in-memory preflight cap, and the operation has a finite time budget. This is **not** a reservation or proof of durability.
- Rules and the public approved core may transiently occupy disk blocks/page cache despite having no name. `O_TMPFILE` does **not** promise forensic secure erasure, encryption of plaintext blocks, or durable protection from the same UID/root. This slice does not extract credential-bearing SQLite or node data.
- No fd or executable pathname is published, no `linkat` is used, and the original core binary is **never executed** by this operation. This proof of ephemeral materializability is NOT a cross-restart resource lease, importer, transaction or core checker.
- The current live daemon, `apply_journal`, saved inert journal, subscription state and TUI are not modified. Existing encrypted candidates survive failure. No new HTTP/CLI/TUI route is introduced.

## Verification and follow-up

Unit tests cover a journal-bound rule set, repeat probing with no directory entries, wrong key, canceled context, unsafe parent mode/symlink, stale current selection, abandoned journal, directory replacement, corrupt/truncated payload, and `Close` serialization. The managed-core integration exercises the **real repository-locked** Linux sing-box binary as an anonymous, non-executable resource. CI / race / integration results are tracked in draft PR #1.

True restore still needs isolated SQLite import/migration, portable native rule path rebinding, durable resource pins tied to the target generation, an operation-gated same-transaction CAS + recovery journal, actual core Check/Activate/Verify, rollback-of-rollback and SIGKILL/power-loss tests. T15/T23, CN offline resource licensing/distribution closure and 72h/7d/30d durability tests remain release blockers; neither this probe nor a successful CI run changes that.
