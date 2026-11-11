# ADR 0197 — Fsync the leased parent after encrypted temporary-file reclamation

Status: draft implementation; requires PR #76 integration and exact-head CI (M5 reliability slice).

## Context

ADR 0195/0196 anchor explicit candidate Discard and failed Stage empty
scope cleanup to the original parent directory inode. The encrypted
archive retention reclaimer already acquires an exclusive parent flock
and uses `unlinkat(parent_fd, temporary_name)` to remove only recognized
unlocked single-linked 0600 v2 temporary ciphertext files.

After one or more unlinks, however, the reclaimer called
`syncSealedArchiveDir(parent_path)`. That reopens an absolute pathname.
An uncooperative same-UID process can rename the parent despite the
advisory flock and substitute an unrelated private directory or a
symlink at that pathname after unlink and before fsync. Consequently,
the durability operation could sync the wrong inode.

## Decision

- Require the canonical private parent pathname to still name the
  inode held by the reclaimer's exclusive flock before every
  destructive temporary-file unlink. The helper validates the same
  UID-owned 0700 ancestor policy before comparing `os.SameFile`.
- After the last successful unlink, call `lock.Sync()` on the *same
  parent fd* rather than `syncSealedArchiveDir(parent_path)`.
  Check the parent fd/path identity immediately before and after the
  durability barrier, including the final no-op case.
- Introduce a private, nonproduction `beforeParentSync` test hook
  after the last unlink. The public `ReclaimAbandonedSealedArchives`
  signature, candidate cap, file flock, error sentinel, no-recursive
  deletion rules, and published archive retention are unchanged.
- A refusal **after** unlink must return an error, even when the
  bounded report accurately counts a removed orphan. The durability
  outcome may be uncertain and must not be silently retried or
  represented as successful reclamation.

## Regression

Linux regressions create a single owner-private, single-linked
unlocked v2 temporary file, inject a parent directory rename exactly
after its unlink, and replace the original path with either a second
owner-private directory or a symlink. Reclamation must fail closed,
the original parent must have lost only its known orphan, the foreign
sentinel must survive, and no path-based cleanup may follow the swap.

A healthy parent with no orphan does not invoke the destructive
checkpoint; when it contains one orphan, reclamation removes only
that file and succeeds using the pinned fd durability barrier.
Existing retention tests continue to cover active writer flocks,
SIGKILL, hardlinks, legacy files, published archives, quotas, and
parallel writers.

## Limitations and release holds

An inode comparison immediately before `unlinkat` is still not an
atomic compare-and-unlink against a same-UID attacker racing child
directory entries under the *same* leased parent inode. This slice
does not pin encrypted archive publication and `createLeasedSealedArchiveTemp`
or other pathname-based temp operations, and it does not establish
Issue #59's intermittent candidate staging root cause.

No live restore, automatic candidate GC, T15/T23/T20/T25 acceptance,
CN offline resource redistribution, or release is authorized. Preserve
Linux ordinary-user operation without TUN, the five-layer routing model
without subscription/ISP routing sources, the approved Core and stable
`main` baseline. Merge only after PR #76 has landed and the exact
combined head passes ordinary CI, all four Go Race shards, Managed
Core Integration, and native Linux amd64/arm64 Core Provenance.
