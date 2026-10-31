# ADR 0187 — Locked-directory read evidence and reopen post-preflight identity

Status: Draft implementation; exact-head CI pending (M5, T15/T23).

## Problem

ADR 0186 anchored creation of the candidate ciphertext to the leased
directory fd. Reading remained path-based in `inspectInertCandidateFile`:
it first compared the directory fd with its pathname, scanned the original
child, then opened `candidate.ktbackup` by full path. A same-UID actor
that ignored the advisory flock could rename the directory after ReadDir,
substitute a different 0700 directory containing a 0600 ciphertext file,
and cause the inspection to return the substituted file's identity.
`O_NOFOLLOW` on the leaf does not constrain intermediate components.

Likewise, `ReopenInertRestoreCandidate` performed its full authenticated
preflight after a single initial inspection but returned a candidate
without a final fd/path and archive identity check. The path could have
been switched after the last authenticated pass.

## Decision

- Keep the original directory flock throughout inspection. Use
  `openat(leased_dir_fd, "candidate.ktbackup", O_RDONLY|O_NOFOLLOW|
  O_CLOEXEC)` for the ciphertext leaf. Preserve private file-mode,
  UID/one-link checks, exact source-map of allowed child entries,
  fd/path identity parity and the existing read-only nature.
- Revalidate the child directory fd/path identity after leaf inspection.
- After a Reopen authenticated preflight, inspect the leased ciphertext
  again, matching the original inode, size and modification time
  before returning any retained candidate. A private test-only hook
  allows a deterministic path swap at this boundary; the exported
  Reopen API and error sentinels remain unchanged.
- Use the existing leased directory fd for fsync of the ciphertext
  creation and Discard unlink rather than reopening a potentially
  substituted pathname. Parent sync remains separately validated.

## Evidence and limits

A synthetic Linux fixture swaps the directory pathname after the
locked child inventory but before the archive open, using either a
foreign private 0700 directory containing a 0600 file or a symlink to
one. Inspection must fail closed without mutating either file. An
authenticated encrypted-archive fixture renames the candidate scope
after preflight and ensures Reopen refuses, preserving both the
original ciphertext and the substituted scope.

The multi-pass authenticated preflight itself still uses a pathname
and does not cryptographically bind every intermediate open to the
leased directory fd. The post-preflight checks narrow but cannot
eliminate all same-UID TOCTOU windows; a malicious actor could alter
paths and restore them between checks. Future descriptor-bound preflight
will require a separately reviewed trust-boundary design.

No claim of root cause for Issue #59's intermittent create_scope failure,
actual restore support, T15/T23 completion or broader release readiness.
Issue #59 stays open. No TUN, subscription/ISP route source, automatic
retry, Core pin, network policy or stable main changes. Merge only after
exact-head ordinary CI, Race 4/4, Managed Core and native amd64/arm64
Core Provenance have all passed.
