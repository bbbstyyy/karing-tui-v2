# ADR 0190 — Create inert candidate scopes relative to the leased parent inode

Status: draft implementation, pending exact-head CI (M5 T15/T23 partial).

## Context

Candidate staging already holds an exclusive flock on a private, owner-only
parent directory and uses directory-relative `openat` for encrypted child
ciphertext. Scope creation still called `os.MkdirTemp(candidateParent, prefix)`
by pathname. Since Linux directory flock is advisory, a same-UID actor
ignoring it could rename the leased parent and replace its canonical
path between inventory inspection and MkdirTemp. In that case path-based
creation could write a directory in an unrelated replacement.

## Decision

- Generate a bounded number (eight) of cryptographically random 96-bit
  names under the existing restore-candidate prefix, with no path fallback.
- Create new 0700 scopes using `mkdirat(parent_flock_fd, name, 0700)`;
  open the new child via `openat(parent_flock_fd, name, O_DIRECTORY|O_NOFOLLOW)`
  to collect its initial inode identity from the same leased parent.
- Before pathname-based adoption, require the **parent path** still points to
  the leased parent inode and the child path still points to the inode
  captured from the leased parent. Compare that inode against the subsequent
  candidate child lease as before.
- Use `parentLock.Sync()` while the parent lock is held, rather than
  fsyncing a potentially replaced parent pathname.
- Retain the public fail-closed sentinel, fixed-class private syscall
  diagnostics, bounded retries and existing short candidate lease scope.

## Test contract

The synthetic stage probe swaps the parent **after the parent inventory and
before mkdirat**, replacing its old pathname with either another owner-private
directory or a symlink. The scope must be created only under the original
leased parent inode; the replacement must remain empty; staging must refuse
adoption and never remove an unrelated path. A direct helper test verifies
the returned identity is from the leased parent even after a path swap.
The existing phase test additionally exercises an injected refusal at the
new fixed checkpoint `scope_before_mkdirat`.

## Limits

With an uncooperative same-UID actor, a renamed parent may retain a newly
created, empty 0700 scope. Production deliberately avoids guessing an
untrusted path for cleanup. There is no atomic compare-and-unlink here;
directory-entry and post-check races are not fully eliminated. The entire
multi-pass archive preflight is not yet fd-bound. This slice neither
explains Issue #59's intermittent `create_scope` refusal nor authorizes
live restore, GC, T15/T23, long soaks, CN rule redistribution, or release.
No Core change, TUN, subscription/ISP routing, or stable main modification.

Merge only after exact-head ordinary CI, all four Go Race shards, Managed
Core Integration, and native Linux amd64/arm64 Core Provenance succeed.
