# ADR 0196 — Anchor failed-Stage empty scope cleanup to the leased parent fd

Status: draft, pending stacked PR #75 and exact-head CI (M5 T15/T23 partial).

## Context

A failed Stage may attempt to remove its freshly created empty private
candidate directory before the candidate child lease has been acquired.
The existing `removeNewEmptyInertScopeIfIdentical(path, created)`
verified the child pathname/inode and then called `os.Remove(path)`.

ADR 0190 anchored `mkdirat` creation to the flocked parent directory,
but this early cleanup still used an absolute pathname. A same-UID
process ignoring the advisory flock can rename the original parent,
create another owner-private 0700 directory at the old parent path,
and **move the original empty child inode into that replacement**.
The child pathname and inode then match the original creation receipt;
the old path-based cleanup can delete a child in a parent not covered
by its reserved parent lease.

## Decision

- Change the private cleanup helper to require the *already flocked*
  parent fd. Only the two early pre-adoption Stage cleanup call sites
  use it; there is no new public API or stored identity.
- Before any deletion, verify the canonical parent path is still the
  leased parent inode, and the child path is the originally created
  empty candidate. Open that child via `openat(parent_fd, name,
  O_DIRECTORY|O_NOFOLLOW)`, require its fd inode to match the original
  creation identity, and recheck the parent and child path identities.
- Use `unix.Unlinkat(parent_fd, name, AT_REMOVEDIR)` to delete only an
  empty directory entry from the leased parent inode; nonempty scopes
  fail closed (never recursively delete ciphertext or unknown files).
  Persist the deletion with `parent_fd.Sync()` and verify the parent
  pathname still names the leased inode. No absolute-path deletion
  fallback.
- The short parent reservation flock remains held during this early
  cleanup. The helper is not called after the child lease is acquired;
  post-adoption explicit Discard retains ADR 0195's separate checks.

## Linux regression contract

1. Create a scope through the leased parent, rename the parent, replace
   its original pathname with a fresh private 0700 parent, then move
   the *same original empty child inode* into it. The old child-only
   inode guard would pass; cleanup must now refuse and preserve that
   directory and the replacement parent's sentinel.
2. Keep a normal leased parent but put an unknown file inside the
   newly created scope. The early cleanup may not delete the
   nonempty candidate or unknown file.
3. End-to-end encrypted Stage probe injects the parent swap and
   same-child move at `scope_created` while refusing further Stage
   progress. The original empty child and source encrypted archive
   survive; the foreign sentinel is untouched.
4. Existing phase tests verify ordinary pre-adoption refusals still
   remove only their own empty created scope, preserving quota and
   preventing accumulation on normal failures.

## Limitations

Even with fd-relative unlink, child inode comparison and the unlink
syscall are separate observations. This is not an atomic
compare-and-unlink guarantee against a hostile same-UID actor racing
directory entries inside the original parent. On uncertain ownership
cleanup must refuse; an empty candidate may be retained for explicit
test-owner remediation. It does not enable automated GC, live restore,
T15/T23/T20/T25 completion or release, and it does not resolve the
intermittent Issue #59 create_scope refusal. The multipart encrypted
HMAC/SQLite preflight remains partly pathname-based.

Keep Linux ordinary-user/no-TUN, CN preset and five-layer routing
without subscription/ISP routing sources, approved Core and stable
`main` unchanged. Merge only after stacked PR #75 lands and the
resulting exact head passes ordinary CI, all four Go Race shards,
Managed Core Integration and Linux amd64/arm64 native provenance.
