# ADR 0206 — Reuse held source/candidate directory descriptors for full inert preflight

Status: Draft, internal M5 T15/T23 hardening; stacked on ADR 0205.

## Gap and decision

ADR 0204 retains the original source parent and exact archive file inode
through candidate Stage. ADR 0205 makes each Preflight's HMAC, full-ciphertext
inventory replay and SQLite logical replay use one fd, yet Stage still invoked
the standalone Preflight which reopened the source parent's pathname.
Likewise Stage's final candidate check, post-crash Reopen and active Verify
reopened the candidate directory by pathname despite already holding its
exclusive flock and original inode.

Extract strictly package-private `preflightInertArchiveAtParent` with
a test-only probe variant. They **borrow** a caller-owned directory fd after
checking its canonical name and strict owner-private path/inode identity,
never close it, never reopen the parent, and retain complete AES-CTR/HMAC,
resource SHA/EOF authentication, full encrypted inventory/SQLite replays,
and SQLite in-memory schema/domain checks. Public `PreflightInertArchive`
continues to obtain and close its own descriptor.

Stage first authenticates through its *already pinned source parent fd*,
still checks the separately pinned original source file inode before/after,
and finishes candidate verification through its *already flocked candidate
directory fd*. Reopen and Verify likewise borrow their held candidate
directory flock fd for every encrypted read. No new public API, file format,
plaintext output, automatic retry, restore or cleanup permission is created.

## Linux regression and safety

- A test-only Stage checkpoint immediately after pinning source parent and
  file fds (before its first full Preflight) swaps the original source parent
  for a private directory or symlink containing byte-identical ciphertext;
  Stage must fail closed with no candidate created or foreign-file changes.
- Full encrypted Stage -> borrowed Preflight -> Verify -> Close -> Reopen ->
  Verify remain healthy with identical read-only reports, and original
  caller-owned directory descriptors remain open.
  `RestoreReady` and `RestoreSupported` remain false.
- A deterministic test-only callback after borrowed parent admission but
  before the first HMAC swaps a locked candidate scope for another
  owner-private directory or symlink with byte-identical valid ciphertext
  and a foreign sentinel. Preflight refuses and returns an empty report,
  preserving both copies and the original caller's flock fd.
- An unrelated valid parent fd cannot be borrowed for the archive even if
  the unrelated parent contains the same authenticated ciphertext; rejected
  descriptor ownership stays with the caller.

## Boundaries and merge gate

The parent inode is anchored for one operation; the original archive leaf
is still reopened via `openat` for independent authenticated passes.
This does **not** provide atomic compare-and-open for hostile same-UID
changes of entries inside the original parent inode, nor prove resolution
of Issue #59's intermittent scope creation refusal.

No live restore, automatic candidate GC, T15/T23/T20/T25 acceptance,
licensed CN offline resource claim or production release. Preserve Linux
unprivileged/no TUN, Karing's five-layer routing without subscription/ISP
routing sources, pinned Core, and stable `main`.

After ADR 0205 passes exact-head CI and merges, retarget to the development
branch and integrate its latest head. Merge only after the new exact-head
ordinary Go tests, all four Race shards, Managed Core Integration and
native Linux amd64/arm64 Core Provenance succeed.
