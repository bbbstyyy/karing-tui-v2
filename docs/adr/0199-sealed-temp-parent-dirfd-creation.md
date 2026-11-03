# ADR 0199 — Create encrypted v2 staging files relative to the leased parent inode

Status: draft M5 hardening; stacked on ADR 0198 and pending exact-head CI.

## Context

ADR 0197/0198 use the original exclusive-flocked parent directory descriptor
for v2 encrypted archive temporary retention fsync and inventory. But the
writer's `createLeasedSealedArchiveTemp` still called
`os.CreateTemp(parent_path, prefix)` **after** its inventory check, which
re-resolves the mutable parent pathname. A noncooperating same-UID process
can rename the flocked directory and replace the canonical path with a
different private 0700 directory before CreateTemp, causing the writer
to create and later lock a file in the wrong parent.

A second gap was the parent-lock-close and temporary-file-flock failure
cleanup: it used `os.Remove(new_temp_path)` after an inode observation,
and could operate through a subsequently replaced absolute path.

## Decision

- Generate a bounded sequence of eight cryptographically random 96-bit
  lowercase hex suffixes after the existing v2 staging prefix. Each new
  file is opened with `openat(parent_flock_fd, name,
  O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600)`. No pathname-based
  fallback or unbounded retry is allowed.
- Verify that the originally flocked parent inode still matches the
  canonical owner-private path, the created fd is current-UID-owned,
  single-linked, regular 0600, and that its inode matches the name
  under the same path before admitting a temp lease.
- Acquire the existing exclusive nonblocking **file flock** before
  releasing the short parent reservation flock. Preserve the exact
  quota policy, active-file accounting and no publication overwrite.
- If acquiring the file flock fails, delete the just-created temp only
  through `unlinkat(leased_parent_fd, file_name)` after checking
  parent and file identity, then fsync the leased parent fd. If any
  ownership or pathname check fails, refuse deletion rather than guess.
- If closing the parent flock fails, do **not** fall back to absolute
  `os.Remove` for cleanup when the fd may no longer be usable. Close
  the new file, fail closed and let the guarded orphan reclaimer
  handle a safely identifiable leftover.
- A package-private `afterInventory` checkpoint tests parent rename
  after quota inspection. A separate low-level `beforeOpen` checkpoint
  tests an adversarial rename after the initial identity check but
  before the dirfd-relative creation. Neither callback is public.

## Linux regression contract

- If the parent path is swapped after the lower-level pre-open check,
  `openat` may create an empty temp only in the **original leased
  parent inode**. The operation refuses to return a usable file lease
  and must never modify the replacement private parent or symlink
  target. A residual original-inode temp is explicitly preferable to
  deleting a guessed pathname.
- After high-level inventory, replace the parent path with an unrelated
  owner-private directory or symlink before temp creation. Admission
  must reject with no new temp in either parent and no foreign
  sentinel modification.
- Replacing the just-created file's name with a different inode must
  make guarded cleanup refuse, preserving the foreign replacement.
  Normal scoped creation, fd-relative cleanup and explicit v2
  abandoned-temporary reclamation must continue to work.
- Existing SIGKILL/active writer, completed archive retention,
  concurrent writer slot, Go Race, native Core provenance and
  Managed Core regressions remain authoritative.

## Remaining risks and release holds

This is not an atomic pathname/inode reservation against a hostile same-UID
process that races entries **inside** the original parent inode. The
`SealInertArchive` publishing path still uses pathname-based hard-link
creation, removal and parent fsync; its checks and error cleanup need
separate review before any release claims. A foreign rename at the
wrong time may retain an inaccessible abandoned temp; never remove
unknown files or recursively clean directories to compensate.

This does not root-cause Issue #59, authorize live restore/automatic
candidate GC, or close T15/T23/T20/T25, licensed offline CN assets,
or the M5 release gate. Preserve ordinary Linux operation with
no TUN, five-layer Karing-style routing with subscription/ISP routing
sources removed, approved Core pin and stable `main` unchanged.

Merge only after PR #78 (ADR 0198) has landed, the branch has been
retargeted to `feat/m0-m1-foundation`, and the integrated exact-head
ordinary CI, all four Go Race shards, Managed Core Integration and
native Linux amd64/arm64 Core Provenance have passed.
