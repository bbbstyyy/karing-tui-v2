# ADR 0195 — Bound explicit candidate Discard to the original parent dirfd

Status: draft implementation, pending exact-head CI and prior PR #74 merge (M5 T15/T23 partial).

## Context

Prior ADRs anchored candidate creation, inventory, child opens and Stage's
post-copy parent fsync to verified directory descriptors. ADR 0194 additionally
retains the original parent's inode identity for the active candidate lease.

Explicit internal `Discard` still removed the encrypted ciphertext using
`unlinkat(leased_child_fd, "candidate.ktbackup")`, synced that child inode,
then removed the directory with `os.Remove(candidate.directory)` and
synced the parent with `syncSealedArchiveDir(candidate.parent)`. The final
two operations re-resolved absolute paths. A same-UID process ignoring an
advisory flock can substitute the candidate parent pathname between the
last child identity check and these operations. The old implementation could
remove a different, empty same-name private scope or fsync a foreign parent.

## Decision

- Before any irreversible cleanup operation, open the original parent with
  `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` and require its fd identity to match
  the owner-private 0700 parent inode recorded in ADR 0194. Reject
  path substitution without fallback.
- Keep the exclusive child lease and the existing one-leaf inventory
  constraints. Remove the known ciphertext only through the locked child
  dirfd; fsync that same child descriptor.
- Before deleting the now-empty child directory, revalidate the pinned
  parent fd/path identity and the original child fd/path identity.
  Remove the child directory entry relative to the parent fd using
  `unix.Unlinkat(parent_fd, child_name, AT_REMOVEDIR)`, never
  `os.Remove(absolute_path)`.
- Sync the pinned original parent fd and verify the parent path
  identity again. Never open a potentially substituted parent by name
  for this final durability sync.
- Keep the public `Discard(ctx)` signature, a private single-stage
  fail-closed sentinel, no recursive deletion, no GC automation, and a
  bounded test-only hook after leaf unlink but before directory unlink.

## Linux regression contract

A full encrypted Stage fixture exercises normal explicit Discard and
ensures only its own candidate is removed while the source archive remains.

A separate fixture injects the replacement of the original parent after
the known ciphertext has been unlinked from the locked child and before
the final directory unlink. The parent is replaced by either a new
owner-private directory or a symlink targeting one, containing a
**same-name empty child directory**. Under the previous path-based
`os.Remove`, this foreign empty child could have been deleted.
The operation must now fail closed, preserve the original empty scope
under the moved parent, leave the forged empty directory and sentinel
untouched, and retain the original encrypted source archive.

A direct helper test verifies that the pinned parent descriptor still
identifies the original inode after rename and refuses a new private
parent at the original pathname.

## Safety limitations and release holds

This does not make separate inode check and `unlinkat` system calls
atomic against an uncooperative same-UID process. In particular, a
malicious actor can still race directory entries *within the pinned
parent inode* after the identity checks. For a failed Discard that
already removed its recognized ciphertext, an empty original scope
can remain; Discard is not a transactional rollback or automated GC.

The whole multi-pass encrypted HMAC/SQLite preflight still has
pathname-based sections. This does not root-cause Issue #59 or enable
actual restoration, candidate GC, T15/T23 or T20/T25 acceptance, CN
offline license/resource release, or stable release. Preserve Linux
ordinary-user/no-TUN operation, five-layer routing without
subscription/ISP routing, approved Core and stable main.

Merge only after PR #74 integration, exact-head ordinary CI, all four
Race shards, Managed Core Integration, and native Linux amd64/arm64
Core Provenance successfully complete.
