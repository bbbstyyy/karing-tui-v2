# ADR 0193 — Pin restore candidate parent inode through post-copy fsync

Status: draft implementation pending exact-head CI (M5 T15/T23 partial).

## Context

ADR 0190 bound candidate creation and its *first* parent fsync to the
leased parent directory fd. ADR 0191/0192 bound child lease opening and
inventory to the same inode. However, after the short parent flock
was released, Stage copied ciphertext and then called
`syncSealedArchiveDir(candidateParent)` by its absolute pathname.

The parent flock is advisory. A same-UID actor can replace that
pathname during ciphertext copy with another private 0700 directory.
Path-based fsync can then operate on the replacement rather than
the parent whose inode reserved and created the candidate.

## Decision

- While the parent flock is held, open an **independent directory
  descriptor** with `openat(leased_parent_fd, ".")` and validate its
  inode, ownership and 0700 mode through the existing parent inventory
  reader helper.
- Retain this non-flocked descriptor only through the bounded Stage
  operation; release the exclusive parent flock before ciphertext
  copy as before, so ordinary concurrent reservations are not blocked
  by lengthy authentication or IO.
- Replace the post-copy path-based parent fsync with a helper that
  requires the canonical parent path still identify the *pinned*
  inode before and after calling `pinned.Sync()`. Never fsync a new
  path target as a fallback. Reject a null/closed or stale descriptor.
- Recheck pinned parent inode/path identity at final Stage admission,
  in addition to the existing candidate child identity and full
  cryptographic/SQLite preflight.
- Always close the independent descriptor on Stage exit. Preserve
  fail-closed error sentinels, bounded budgets and no retry.

## Regression

Linux tests keep the short parent flock separate from the pinned
descriptor, verify sync succeeds after the flock closes, then rename
the original parent and replace the path with another private 0700
directory or a symlink. The pinned descriptor must still refer to the
original inode and sync admission must fail.

A full encrypted Stage fixture injects the same parent replacement
at the existing `parent_sync` phase, after ciphertext copy. Stage
must reject the candidate, leave the authenticated source unchanged,
retain the original ciphertext without guessing an unsafe cleanup path
and avoid modifying the foreign replacement/sentinel.

## Limits and release holds

The pinned fd does not provide an exclusive parent flock throughout
ciphertext IO, nor solve all same-UID directory races or the
path-based multi-pass HMAC/SQLite preflight. Discard and other
filesystem durability pathways require separate review. This slice
does not root-cause Issue #59's intermittent `create_scope` refusal,
authorize live restoration/GC, or close T15/T23, T20/T25, CN license
and offline rule closure, or stable release. Linux no-TUN operation,
five-layer routing without subscription/ISP sources, approved Core
and stable main remain unchanged.

Merge only after exact-head ordinary CI, all four Go Race shards,
Managed Core Integration, and native Linux amd64/arm64 Core Provenance
are successful.
