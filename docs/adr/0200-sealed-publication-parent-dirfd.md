# ADR 0200 — Pin the encrypted archive publication parent and use dirfd-relative link/unlink/fsync

Status: draft M5 implementation; stacked on ADR 0199 and pending exact-head CI.

## Context

ADRs 0197–0199 anchored sealed v2 staging retention, inventory, and creation
to the original 0700 directory inode. Once `SealInertArchive` wrote and
authenticated an encrypted temporary file, its publication still performed
`os.Link(temp_absolute_path, destination_absolute_path)`,
`os.Remove(temp_absolute_path)`, and
`syncSealedArchiveDir(parent_absolute_path)`. Its failed-write defer
likewise used an absolute-path `os.Remove`.

A same-UID actor ignoring advisory file locks can substitute the parent
pathname after the writer's reservation lock is released, making any
of those path-based operations act on an unrelated private directory.
Publishing to a pre-existing destination must remain impossible.

## Decision

- Immediately after acquiring the v2 temp file lease, open a separate,
  non-flocked `O_DIRECTORY|O_NOFOLLOW` parent descriptor and verify it
  owns the **same exact live temp inode** through `openat(parent_fd,
  temporary_name)`. Do not retain the short exclusive reservation flock
  across archive encryption, Core copying, hashing or fsync.
- Before publication, require the parent fd/path identity still match
  and the temp source entry, writer fd and pathname match the same
  single-linked, current-UID-owned regular 0600 inode.
- Publish using `unix.Linkat(parent_fd, temporary_name, parent_fd,
  destination_name, 0)`. Existing destination entries (including
  symlinks) cannot be overwritten; the syscall itself is authoritative
  in the presence of competing creators.
- Once a hard link is made, mark the outcome as **possibly published**
  even if any post-link validation or fsync fails. Check that the
  published destination fd, canonical path and writer fd identify
  the same inode, and that the original temp now has two links.
- Only with matching original parent identity, remove the temp name
  through `unix.Unlinkat(parent_fd, temp_name, 0)`. Sync **that same
  parent fd**, then verify its canonical inode identity again.
- For any *pre-link* write failure, attempt guarded cleanup through
  the already-pinned parent fd using the existing single-linked
  original-temp identity checks. Never fall back to absolute-path
  deletion. Keep the temp's exclusive file flock until cleanup or
  publication has completed.
- Add strictly package-private before-link/after-link test hooks.
  Production always passes nil; no external API, persistence, file
  format, encryption, or user-facing restore authority changes.

## Linux regression contract

1. A healthy private parent publishes an encrypted staging inode once,
   removes the temp name and leaves the published file single-linked,
   0600 and byte-identical. A competing destination cannot be replaced.
2. If the source temp name is replaced with a different inode, both
   publication and guarded failure cleanup refuse. The foreign
   replacement remains untouched.
3. With a live writer fd and pinned parent fd, inject a parent rename
   immediately before `linkat` or after `linkat`, and replace its
   canonical path with another 0700 directory or a symlink target.
   A hard-link operation may complete **only inside the original
   pinned inode**, but the caller must report an unsafe/uncertain
   outcome. Both original links survive the refusal; the foreign
   parent's unrelated sentinel and contents remain unchanged.
4. Existing full encrypted-archive roundtrip, destination-no-overwrite,
   retention quotas, and real approved-Core integration continue to
   guard normal success behavior.

## Limits and release holds

This pins the *parent inode*, but separate source-name inode checks
and `linkat` are not atomic against a hostile same-UID process racing
entries **inside** that same inode. If such a race causes an unexpected
linked inode, the operation fails closed after verification but the
new directory entry may already exist. Never automatically delete an
uncertain published destination or retry after an ambiguous error.
The separate offline Verify/preflight reader paths still include
pathname-based checks requiring further review.

This does not identify Issue #59's intermittent create_scope failure,
authorize actual restoration or candidate auto-GC, or close T15/T23,
T20/T25, licensed CN offline preset assets, or the M5 release gate.
Maintain ordinary Linux execution without TUN, Karing's multilayer
routing with subscription/ISP route sources excluded, the approved
Core pin, and stable `main` unchanged.

Merge only after PR #79 is integrated into the development branch and
the final exact head passes ordinary CI, all four Go Race shards,
Managed Core Integration, and native Linux amd64/arm64 Core Provenance.
