# ADR 0205 — Share the initial Preflight parent fd with its full HMAC verification

Status: Draft M5 T15/T23 security hardening; stacked on ADR 0204.

## Context

ADR 0202 pins a strict owner-private parent directory inode across
Preflight's complete HMAC verification, full-ciphertext inventory replay
and full-ciphertext SQLite snapshot replay. The manifest and SQLite
readers already use `openat` on that pinned descriptor. But
`preflightInertArchiveProbed` still called the PUBLIC
`VerifyInertArchive`, which independently opened the canonical
parent pathname and captured a **different parent descriptor** for its
first HMAC read.

A noncooperating same-UID process can rename the original 0700 parent
after Preflight captures its fd, substitute another 0700 parent or a
symlink containing an identically named, **byte-for-byte valid**
encrypted archive, and cause the independent first Verify to read
the unrelated parent. A final identity check can later reject this
drift, but reading from the wrong inode at all violates the intended
cross-pass source custody boundary.

## Decision

- Keep standalone `VerifyInertArchive(ctx,path,key)` and its
  package-private `verifyInertArchiveProbed` callbacks unchanged.
  They pin their own non-flocked, strict owner-private read-only
  parent fd for a single complete AES-CTR/HMAC/digest/EOF pass.
- Extract `verifyInertArchiveAtParentProbed` as a strictly internal
  implementation which accepts a **caller-owned, already pinned**
  directory descriptor. It validates `parent.Name() == Dir(path)`,
  the parent fd/path inode identity, and uses the shared
  `openSealedArchiveAtPinnedParent` helper to open the exact
  encrypted basename with `O_NOFOLLOW|O_NONBLOCK`. It never closes
  the caller's directory descriptor.
- Have Preflight pass its original parent fd into the **first** full
  HMAC verification, so all three authenticated passes refer to the
  *same exact parent directory inode* instead of selecting distinct
  parent descriptors from a mutable pathname.
- Keep the existing complete SHA-256, HMAC, decrypted resource digest,
  manifest, SQLite logical validation, exact EOF, mode/UID/single-link
  and file inode checks. Parent identity is rechecked at each stage.
- Introduce one package-private, nil-in-production
  `beforeVerify` checkpoint after Preflight captures its parent fd
  and before it invokes full Verify. The public Preflight signature,
  existing after-auth/after-inventory test hooks, format, receipt,
  encryption key handling and timers are unchanged.

## Linux regression contract

1. Create a genuinely authenticated v2 archive and verify healthy
   standalone Verify and full read-only SQLite Preflight. Verify the
   caller-owned shared directory descriptor remains open and its
   original inode is unchanged after a complete HMAC pass.
2. At the new pre-Verify checkpoint, rename the parent and substitute
   another private directory or a symlink pointing to one. Include
   a byte-for-byte **identical valid archive** and unrelated sentinel
   in the substitute. Preflight must refuse and return an empty
   report without modifying either archive or sentinel.
3. At the same checkpoint, move the **same original file inode** to
   the canonical archive pathname under a newly created private
   parent. Authentication material is unchanged, but Preflight must
   refuse changed parent custody.
4. Supplying a caller-owned fd for a **different** owner-private
   directory, even one containing byte-identical ciphertext, must
   be rejected without closing that fd or reading the foreign file.

## Limits and release holds

These checks pin the directory inode for one call and fail closed
on observed namespace drift, but they are not an atomic compare-and-open
against a noncooperating same-UID process racing directory entries
inside the original inode or swapping/replacing paths between checks.
A fresh call still establishes a new parent identity; the existing
candidate source pinning in ADR 0204 addresses custody across Stage,
not persistent multi-process origin attestation.

Issue #59's intermittent `create_scope` failure remains OPEN:
ADR 0203 improves diagnostic coverage but is not a causal fix.
This change does not enable live restore, automatic candidate GC,
close T15/T23/T20/T25 or CN offline rule-license requirements, or
authorize release. Maintain Linux ordinary-user/no TUN, Karing's
five-layer rule order with subscription/ISP route sources removed,
approved Core pinning and the unchanged stable `main` branch.

After PR #84 (ADR 0204) merges, retarget this Draft PR to
`feat/m0-m1-foundation` and revalidate the final exact head with
ordinary CI, all four Go Race shards, Managed Core Integration and
both native linux-amd64/linux-arm64 Core Provenance jobs before merge.
