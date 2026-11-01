# ADR 0192 — Inspect candidate parent entries through leased parent fd

Status: draft implementation, pending exact-head CI (M5 T15/T23 partial).

## Context

ADR 0190/0191 bound candidate directory creation and Stage/Reopen child lease
opens to a locked parent inode. `inspectCandidateParent` still consumed
`lock.ReadDir` directly and validated each enumerated child by calling
`verifySealedArchiveParent` on a *joined absolute pathname*.

Direct ReadDir permanently advances the leased descriptor's directory
offset. A second inspection with that descriptor might appear empty.
Moreover, pathname-only checks can inspect a substituted parent containing
a different same-name owner-private 0700 child after the original fd-based
inventory. An advisory flock does not stop a noncooperating same-UID actor.

## Decision

- Open an independent parent inventory stream with
  `openat(leased_parent_fd, ".", O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`.
  Require fd/inode identity and owner-private mode before trusting it.
  ReadDir never consumes the flock descriptor's offset.
- Validate each enumerated child name and directory entry type before
  `openat(leased_parent_fd, child_name, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`.
  Verify its actual fd is a 0700 directory owned by the current UID,
  and its fd inode matches its canonical path's lstat inode.
- Require the parent path to identify the same leased parent inode both
  before inventory and at the end, including the zero-entry case.
  Preserve existing ancestor checks, count cap (eight), context
  cancellation, unknown entry refusal, and no deletion.
- Keep a private post-ReadDir hook for deterministic path-substitution
  regressions. Production always supplies nil; there are no new public
  callbacks, configuration formats, or error disclosures.

## Linux regression contract

1. Repeated scans with the **same live parent flock** each enumerate two
   known owner-private children. A fresh reader reports the same parent
   inode and a fully independent offset. A symlink sibling fails closed;
   nil/closed leases cannot open the inventory.
2. With a single or empty parent, replace the parent pathname immediately
   after the inventory with either another private parent containing a
   same-name child or a symlink to it. The full scan must refuse; a
   separate fd-anchored reader still sees the original parent's entries.
   Child opens through the parent fd must not select the foreign child;
   its sentinel file is unchanged.

## Remaining limitations and release holds

This provides better pathname-substitution detection, **not** atomic
compare-and-unlink or full isolation against a hostile same-UID actor
racing subsequent filesystem accesses. The multi-pass archive HMAC/SQLite
preflight is still path-based and Issue #59's intermittent create_scope
refusal is not root-caused. No live restoration, GC authorization,
T15/T23 acceptance, T20/T25 soak, CN rule/license closure, or stable
release. Keep Linux ordinary-user/no-TUN, no subscription/ISP routing
layer, approved Core, and stable main unchanged.

Merge only after exact-head ordinary CI, Go Race 4/4, Managed Core
Integration and native Linux amd64/arm64 Core Provenance all pass.
