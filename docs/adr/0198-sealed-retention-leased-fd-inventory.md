# ADR 0198 — Inspect encrypted archive retention through the leased parent dirfd

Status: draft M5 implementation; exact-head CI required after ADR 0197 integration.

## Context

ADR 0197 pins the parent fsync after reclaiming abandoned encrypted v2
temporary files. Retention enumeration and per-child inspection still
used `parent.ReadDir`, `os.Lstat(join(parent_path, name))`, and a
pathname-based child open. The flock is advisory, and an uncooperative
same-UID process can rename the leased private 0700 parent and put a
different owner-private directory at its pathname between enumeration
and child inspection. That may cause the inspector to count or lock a
different file from the one in its original inventory.

Reading directly from the long-lived flock fd also advances its
directory offset: a second inspection with that same fd can
misreport a nonempty directory as empty.

## Decision

- Create a **new directory stream for each inventory** via
  `openat(flocked_parent_fd, ".", O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`.
  Verify its inode matches the leased parent and that the parent path
  still identifies the same owner-private inode. The scan must never
  consume the flock descriptor's directory offset.
- Reject unknown entries and nonregular directory entries. Open both
  published archive files and v2 temporary files via
  `openat(flocked_parent_fd, entry_name, O_NOFOLLOW|O_NONBLOCK)` to
  prevent follows, unbounded waits on substituted FIFOs, and a
  pathname-based source switch. Check the actual file descriptor's
  inode against a current `Lstat` of the canonical path, and check
  owner, 0600 mode, size and hardlink count before using it.
- For published archives, close the descriptor after read-only
  validation and continue counting only. For temporary files, keep
  the existing independent `LOCK_EX|LOCK_NB` behavior and reject
  ambiguous unlocked two-link publication residues without deletion.
- Verify the parent fd/path identity before each child and at the
  end, including the zero-entry case. Preserve the 8 published/32
  temporary caps, all original error sentinels, no implicit
  deletion of published/legacy/unknown entries, and explicit
  context cancellation.
- The private `afterInventory` test hook is unavailable to daemon,
  CLI and TUI callers and has no production effect.

## Regression

Linux tests run three inspections using the *same* live parent flock
containing one 0600 completed archive and one unlocked recognized v2
temporary. Every pass must report both and close the temporary
descriptor lease; a separate fresh inventory reader must remain
able to enumerate the same original parent inode. Invalid nil
directory leases must fail closed.

A post-ReadDir injected parent rename replaces the parent pathname
with another owner-private directory or a symlink, each containing
an identically named published or temporary file with different
bytes. The inventory must refuse the substituted parent without
altering either file or its unrelated sentinel.

## Limitations and release holds

These are bounded inode/path observations, **not** atomic
compare-and-unlink against a hostile same-UID actor changing entries
*within the original parent inode*. The publication path and
`createLeasedSealedArchiveTemp` still have pathname-based creation
and cleanup operations requiring independent review; Issue #59's
intermittent candidate creation refusal is not root-caused here.

This is not restore eligibility, automated GC authorization, a
T15/T23 or T20/T25 acceptance, CN rule-license clearance or release
readiness. Keep Linux ordinary-user/no TUN, Karing's preserved
five-layer routing without subscription/ISP routing sources,
approved Core pins and stable `main` unchanged. Merge only after
ADR 0197 merges and the integrated exact-head ordinary CI, all four
Go Race shards, Managed Core Integration and native Linux
amd64/arm64 Provenance are green.
