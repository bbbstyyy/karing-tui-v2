# ADR 0211 — Pin inspected encrypted candidate file inode through explicit Discard

Status: Draft M5 T15/T23 manual candidate deletion safety; stacked on ADR 0210.

## Gap

ADR 0209 keeps the exact inspected candidate ciphertext fd through Reopen
and active Verify's first HMAC and full three-pass preflight. ADR 0210
retains Stage's O_EXCL-created ciphertext fd through its final preflight
and limits failed Stage cleanup to its **own** inode.

The explicit, user-initiated `InertRestoreCandidate.Discard` still calls
`inspectInertCandidateFile`, which checks the single 0600 encrypted leaf
beneath the flocked private child scope but returns only FileInfo and closes
its read fd. Later it opens the original parent and unlinks the same
basename with `unlinkat(locked_child_dirfd, "candidate.ktbackup")`.
An uncooperative same-UID process ignoring advisory flock may replace the
leaf inside the SAME original child directory inode between inspection
and unlink with a different, byte-identical valid ciphertext inode.
The filename, ownership, SHA and HMAC do not prove the target is the one
the user previously inspected. Explicit Discard must fail closed instead
of deleting an unexamined replacement.

## Decision

- Retain a read-only `openat` file descriptor of the **same inspected**
  encrypted leaf inode using the existing ADR 0209
  `pinInspectedInertCandidateCipher`, before opening the parent deletion
  lease. If inspection/second open disagree on inode, size, mode, mtime,
  parent/child directory identity, UID/0600, or single-link policy, abort.
- Add `sameInspectedInertCipherForDiscard`: immediately before
  irreversible ciphertext unlink, require the still-open original fd
  to name the **same previously scanned file inode**, with unchanged
  size, mode, mtime, strict current filename, owner/0600/single-link,
  original locked child inode and original candidate parent identity.
  The borrowed file fd remains open until the attempt completes;
  on any ambiguity, delete nothing and release the directory lease.
- Preserve failed Stage's stricter ADR 0210 target-ownership path:
  it may remove only the exact O_EXCL-created target, or an empty scope
  if Stage never created the leaf. Ordinary explicit Discard does not
  acquire authority to remove a foreign file by SHA comparison.
- Preserve the pre-existing explicit `Discard(ctx)` and private
  `discardLockedProbed(requireFile, beforeDirectoryUnlink)`
  signatures. Introduce only a package-private nil-in-production
  checkpoint `discardLockedBeforeCipherUnlinkProbed` for deterministic
  tests after the file and parent fds are pinned, before unlinkat.
  No new user-facing APIs, automatic GC, restore permission, raw errno
  leakage, plaintext file or core activation is added.

## Deterministic native Linux regression

1. Stage real valid encrypted candidate, then run explicit Discard with a
   test-only callback just before the encrypted leaf unlink. Move the
   original leaf to a safe other name and install a *different file inode*
   of byte-for-byte identical authenticated ciphertext under the original
   basename in the SAME flocked child directory. Discard must refuse,
   close its lease and preserve the original and replacement files,
   candidate scope and unrelated sentinel. Independent read-only
   Preflight still accepts the replacement, proving inode mismatch
   rather than cryptographic invalidity.
2. Mutate only the original leaf's mtime between scanned metadata and
   unlink. Refuse without deleting ciphertext and release the flock fd.
3. Healthy Stage -> Verify -> explicitly requested Discard still removes
   the one precisely inspected encrypted leaf and now-empty scope.
   `RestoreReady` and `RestoreSupported` stay false.

## Boundaries and merge gate

`stat` and `unlinkat` remain separate syscalls: this is NOT atomic
compare-and-unlink and is NOT a guarantee against a continuously racing
non-cooperative same-UID process swapping entries just between checks.
The safe action on detected ambiguity is to refuse and preserve bytes;
there is no automatic retry, candidate garbage collector or release
approval. A future hardened filesystem primitive or stronger external
same-UID process isolation would be needed for an atomic guarantee.

Issue #59 intermittent candidate `create_scope` remains OPEN; these
admission/cleanup changes do not demonstrate its root cause. No
transactional live restore, T15/T23/T20/T25 acceptance, CN offline
licensed rule resources or production release. Preserve unprivileged
Linux without TUN, original Karing five-layer routing excluding
subscription/ISP routing source layers, approved Core pin and stable
`main`.

Draft stacked on PR #90 (ADR 0210). After #90 passes full exact-head
CI and merges into `feat/m0-m1-foundation`, retarget and integrate
this PR, then require ordinary Go CI, Race 4/4, Managed Core
Integration and native Linux amd64/arm64 Core Provenance to succeed
again for the FINAL integrated head before merging.
