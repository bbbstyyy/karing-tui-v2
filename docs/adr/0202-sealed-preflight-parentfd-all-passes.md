# ADR 0202 — Keep one private parent inode through all sealed archive preflight passes

Status: draft implementation pending stacked PR #81 and exact-head CI (M5 T15/T23 partial).

## Context

ADR 0201 binds the read-only `VerifyInertArchive` HMAC pass to an
independent private-parent directory descriptor. However,
`PreflightInertArchive` performs three separate encrypted archive
reads: complete HMAC/resource authentication, complete ciphertext
SHA-256 and manifest replay, then a complete ciphertext and SQLite
snapshot replay. The last two passes still opened the leaf by its
absolute pathname and validated only the *current* private 0700
parent at the beginning of each read.

A noncooperating same-UID process can rename the original parent
after the first or second pass, substitute another owner-private
directory with a **byte-for-byte identical valid archive**, and
satisfy the later HMAC-derived SHA comparisons while changing which
parent inode the preflight inspected. Moving the **same original
archive child inode** beneath a fresh parent has the same problem.

## Decision

- At preflight entry, pin one read-only, non-flocked
  `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` descriptor for the verified
  owner-private archive parent. Retain it through the first full
  Verify/HMAC pass, the inventory replay, the SQLite replay, and
  the final in-memory read-only schema/domain checks.
- Check this pinned fd's identity against the canonical parent path
  after Verify, after inventory, after SQLite bytes, after live-closure
  revalidation and just before returning metadata. Fail closed and
  return an empty preflight report if the parent is substituted.
- The second and third archive reads use
  `openat(pinned_parent_fd, basename,
  O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)`, never pathname-based
  fallback. Preserve their existing bounded full-ciphertext SHA,
  0600/UID/single-link/size/inode checks, manifest digest, exact
  archive receipt comparison, zeroed SQLite bytes and purely
  in-memory SQLite integrity/schema validation.
- Keep the original private `preflightInertArchive(..., afterAuth)`
  test signature and the public `PreflightInertArchive` signature.
  A second strictly internal `afterInventory` callback tests
  the boundary between manifest and SQLite replay. Existing direct
  inventory/SQLite helper signatures remain valid as wrappers that
  establish their own parent descriptor for isolated callers.
- No parent flock, write access, automatic retries, plaintext file,
  public controls, persistent parent identity or restore authority.

## Regression

A valid encrypted archive first passes all three preflight stages.
Then, separately after full Verify and after inventory SHA replay,
inject a parent rename and a replacement owner-private directory or
symlink containing an identically named, **byte-for-byte equal
authenticated ciphertext**. All four cases must return the unsafe
archive sentinel and an empty preflight report, without touching
either archive, sentinel or live state.

After full Verify, also rename the parent, create a replacement
private parent at the original pathname and move the **same original
archive child inode** into it. Preflight must refuse despite file
inode and HMAC staying identical. Existing corruption, bad-key,
SQLite logical, cancelation, manifest and authorized Core tests
remain authoritative.

## Limitations and release holds

This is a process-call scoped parent identity lease, not an atomic
protection against same-UID races inside the original parent inode
or a persisted parent identity across fresh calls. The Verify pass
still opens its own short-lived parent descriptor; checks before
and after cannot establish atomic cross-system-call identity.
Other source-file readers and candidate Stage/Reopen preflights
remain subject to independently reviewed trust boundaries.

This ADR does not root-cause Issue #59's intermittent create_scope
refusal, authorize actual restore or candidate auto-GC, or complete
T15/T23/T20/T25, offline CN asset license requirements, or release
gates. Preserve ordinary Linux no-TUN, Karing's five-layer routing
without subscription/ISP routing sources, pinned native Core,
and unchanged stable `main`.

Merge only after PR #81 is merged into `feat/m0-m1-foundation` and
this exact integrated head has green ordinary CI, all four Go Race
shards, Managed Core Integration and native Linux amd64/arm64
Core Provenance.
