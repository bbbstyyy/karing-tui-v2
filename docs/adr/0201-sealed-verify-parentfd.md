# ADR 0201 — Pin the encrypted archive's parent inode for the full Verify read

Status: draft M5 implementation; stacked on ADR 0200 and subject to exact-head CI.

## Context

ADRs 0197–0200 progressively bound encrypted archive temporary creation,
retention and publication to original private parent dirfds. The read-only
`VerifyInertArchive` path still called `verifySealedArchiveParent(path)`
and then reopened the archive using an **absolute path**. A
noncooperating same-UID process may rename that parent and substitute a
different private 0700 directory containing an identically named,
byte-for-byte valid encrypted archive before the open. Correct HMAC
authentication does not establish that it came from the parent inode
whose namespace was initially validated.

A second drift case is possible after the ciphertext has been opened
and authenticated: the attacker may replace the parent pathname and
move the **same original archive inode** beneath it. Child fd/path
inode checks alone still match, but its parent custody has changed.

## Decision

- Preserve the public `VerifyInertArchive(ctx, path, key)` API, format,
  cryptography and nonsecret receipt. Internally open a read-only
  `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` descriptor for the private
  owner-0700 parent, verifying its inode still matches its canonical
  parent pathname.
- Open the exact archive leaf through
  `openat(pinned_parent_fd, leaf, O_RDONLY|O_NOFOLLOW|O_NONBLOCK)`.
  Never fall back to absolute-path opening after a parent mismatch;
  reject symlinks, nonregular files and wrong leaf identities via the
  existing `verifySealedFile` checks.
- Retain the independent **non-flocked** parent descriptor through
  the complete bounded AES-CTR/HMAC, inventory, digest and EOF scan.
  The absence of a parent flock ensures verification does not block
  normal writer reservations.
- Verify the canonical path still names the original parent inode
  immediately after opening the archive fd and at the very end of
  authentication, in addition to the existing file inode/mode/size,
  HMAC, plaintext digest, EOF and context checks.
- Expose only two strictly package-private test boundaries: after
  parent fd validation but before leaf open, and after successful
  HMAC authentication but before the final inode/path checks.
  Production always calls both with nil; there are no new public
  callbacks, diagnostics, flags or persistent receipts.

## Linux regression contract

1. Verify a valid encrypted fixture normally. Then use the first
   checkpoint to rename its parent and replace that path with a new
   owner-private directory or symlink target containing an exact
   **byte-for-byte copy** of the same valid archive. Verification
   must refuse; neither original nor foreign ciphertext or sentinel
   is modified.
2. During the post-HMAC checkpoint, rename the original parent, create
   a replacement 0700 parent, and move the **same original archive
   inode** to the original canonical archive path. The file fd/path
   identity and HMAC still match; verification must nevertheless
   refuse the parent identity change. Both ciphertext and replacement
   parent's sentinel remain unmodified.
3. Existing encrypted roundtrips, wrong-key, tampering, overflow,
   resource and approved-Core integration checks must stay green.

## Limits and release holds

This pins parent identity only for the lifetime of an individual
verification call. It is not atomic protection against hostile same-UID
actors racing entries within that original parent inode and does not
attest which parent inode a subsequent fresh verification should trust.
In particular, `PreflightInertArchive` and other multi-pass read
paths still include separate pathname opens and need independent review.

It does not establish the root cause of Issue #59's intermittent
candidate staging refusal, authorize live restoration/automatic GC,
close T15/T23/T20/T25 or CN licensed offline assets, or pass the M5
production release gate. Keep Linux ordinary-user/no-TUN operation,
Karing's five-layer routing without subscription/ISP routing sources,
approved Core pins and stable `main` unchanged.

Merge only after PR #80 (ADR 0200) has merged into
`feat/m0-m1-foundation`, and the resulting exact head passes
ordinary CI, all four Go Race shards, Managed Core Integration,
and native Linux amd64/arm64 Core Provenance.
