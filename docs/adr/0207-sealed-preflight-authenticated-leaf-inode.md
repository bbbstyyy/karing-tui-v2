# ADR 0207 — Retain the first authenticated sealed leaf inode through all Preflight passes

Status: Draft M5 T15/T23 security hardening; depends on ADR 0206.

## Gap

ADR 0205 shares one owner-private parent dirfd for the complete three-pass
HMAC, inventory and SQLite Preflight. ADR 0206 also borrows Stage/Reopen/
Verify's existing source/candidate directory leases. However, the encrypted
*file* is separately reopened by `openat(parent_fd, basename)` on each pass.
A noncooperating same-UID process can rename the original 0600 ciphertext
leaf within the **same original parent directory inode** and place another
file of exactly the same authenticated bytes under the old basename.
Parent identity, per-pass inode/path checks and SHA/HMAC all succeed
individually without recognizing that the *file inode* changed mid-call.

## Decision

- Extract strictly private `verifyInertArchiveAtParentPinnedFileProbed`
  from the existing complete HMAC/resource/EOF verifier. The existing
  standalone/public wrapper still closes its file fd. Only the full
  Preflight passes an optional pointer to retain the verified **original
  file descriptor** after complete cryptographic success; failure never
  returns a pin. Ownership is transferred to the full Preflight, which
  closes it at the end of this call, including every error path.
- Add `samePinnedSealedPreflightFile`: require the original HMAC file fd
  and each independent replay fd to refer to the SAME inode, with canonical
  path, UID/0600/single-link, size, mode and mtime checks, plus the original
  private parent fd/path identity. The fd remains open through in-memory
  SQLite logical/schema/domain checks and the final report check.
- Keep public `VerifyInertArchive`, `PreflightInertArchive`, existing
  in-package helper signatures and all independently repeated ciphertext
  SHA-256, AES-CTR/HMAC, resource digest, manifest, exact EOF, SQLite and
  release-blocker checks. New private `...Pinned` helper wrappers add
  the inode cross-check without changing standalone reader behavior.
- Preserve the outer bounded Preflight deadline, key custody and read-only
  behavior. No plaintext file, state mutation, CLI/API enablement, retry,
  candidate discard, automatic GC, or core restart is introduced.

## Deterministic Linux regression

1. Build a real valid encrypted v2 archive and verify the ordinary full
   Preflight succeeds without permitting restore.
2. During one full Preflight, just after HMAC or just after inventory,
   rename only the original encrypted *leaf* within the same private parent
   and atomically move a **different inode** with byte-identical valid
   ciphertext to the old basename. Exercise standalone and borrowed-parent
   entrypoints separately. Each must return a zero report and
   `ErrUnsafeSealedArchive`, preserving both archive bytes, original and
   substitute inodes and an unrelated sentinel.
3. The retained original authenticated file fd must be valid after the
   HMAC verifier returns; a wrong key must refuse without granting a
   retained fd or closing the caller-owned parent fd.

## Boundaries and merge condition

These checks reject persistent same-parent leaf replacements observed at
stage boundaries. They do **not** provide an atomic compare-and-open against
a malicious same-UID process swapping directory entries between syscalls,
or prevent in-place inode mutation that happens and is reversed between
checks. Each pass remains independently SHA/HMAC-audited.

Issue #59 intermittent create_scope refusal remains open and this work is
not its proven root-cause fix. No real restore, automatic candidate GC,
T15/T23/T20/T25 long-soak acceptance, licensed CN offline resources
or production release. Preserve unprivileged Linux/no TUN, original Karing
five-layer routing excluding subscription/ISP sources, approved Core
pin and stable `main`.

Keep stacked on PR #86 (ADR 0206) until it merges, then integrate/retarget
to `feat/m0-m1-foundation`. Only merge the FINAL exact combined head after
ordinary Go CI, all four Go Race shards, Managed Core Integration and
native Linux amd64/arm64 Core Provenance pass.
