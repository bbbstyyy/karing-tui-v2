# ADR 0210 — Retain Stage's created ciphertext inode through final Preflight and fail-safe cleanup

Status: Draft M5 T15/T23 encrypted-candidate custody; stacked on ADR 0209.

## Gap

ADR 0204 pinned the ORIGINAL sealed SOURCE inode for Stage's copy.
ADR 0205-0207 share one candidate directory fd and preserve the HMAC
archive inode across the three independent verification passes; ADR 0208
binds Stage's first SOURCE HMAC to its earlier pin; ADR 0209 similarly
binds candidate Reopen/Verify to an inspected ciphertext leaf.

The candidate ciphertext Stage creates with
`openat(locked_candidate_dirfd, "candidate.ktbackup", O_CREAT|O_EXCL)`
was still **closed before** Stage's final authenticated Preflight.
Another non-cooperating process running as the same UID could rename
the newly created 0600 ciphertext leaf and replace its old basename
inside the SAME locked 0700 directory with a different inode containing
byte-for-byte identical valid ciphertext. A plain final Preflight can
accept the replacement as a new initial HMAC source, while Stage only
rechecks the child *directory* inode afterward.

A second boundary is more serious: failed Stage calls the general
`discardLocked(false)` path, which can unlink ANY single owned,
regular, valid-looking `candidate.ktbackup` in that directory. If
Stage's own leaf was replaced or Stage never created it (O_EXCL
rejected an already-placed foreign file), this cleanup could delete
the foreign file despite never having created its inode.

## Decision

- Add private `copyInertCandidateCipherAtPinnedSourceRetained`, preserving
  the existing package-private helper as a closing wrapper. Its optional
  retained target descriptor transfers to Stage **immediately after**
  successful O_EXCL open, including on subsequent partial-copy failure.
  Direct historical callers keep closing locally. Stage holds the exact
  O_WRONLY-created target descriptor across fsync, parent sync, final
  HMAC/full SHA/resource/inventory/SQLite replays, and final report.
  It supplies that descriptor as the `expectedFile` to ADR 0208's
  internal full Preflight. New HMAC file fd must match the exact original
  target inode *before reading any ciphertext*. The target fd is closed
  on all exits after optional Stage failure cleanup.
- Add strict Stage-specific `discardStageLocked`. A Stage with no
  successfully created target fd may remove an **empty** known scope,
  but may never unlink an existing ciphertext file. Once Stage has
  created a target, cleanup must prove the current single leaf has
  precisely the same inode, mode, length, mtime, owner/0600/single-link
  and original locked directory/parent identity as its retained O_EXCL
  descriptor, checking again immediately before fd-relative unlink.
  If custody is ambiguous, fail closed and **leave the encrypted
  candidate/foreign file in place for explicit manual inspection**.
  All cleanup paths release the candidate flock; no path-based delete
  or automatic garbage collector is introduced.
- Keep existing general `Discard`, private test hook and
  `copyInertCandidateCipherAtPinnedSource` signatures as wrappers
  without changing their semantics. This change is limited to failed
  Stage custody and final Stage Preflight, not a redesign of explicitly
  requested Discard. Preserve encrypted-only handling, full resource
  authentication, SQLite/domain verification, no TUN and no restore.

## Deterministic Linux regressions

1. Healthy encrypted Stage -> Verify -> Close -> Reopen -> Verify still
   succeeds with `RestoreReady=false` and `RestoreSupported=false`.
2. Just before final Stage Preflight, rename the O_EXCL-created leaf
   outside the locked candidate, insert a DIFFERENT inode containing
   byte-identical valid ciphertext under its old name, and keep a foreign
   sentinel. Stage must reject and cleanup must NOT unlink the foreign
   encrypted leaf; both original and foreign ciphertext and the
   sentinel remain byte-identical. Standalone Preflight still accepts
   the foreign bytes, proving the refusal is inode identity.
3. At the private `cipher_before_openat` boundary, place a valid
   foreign file at the target name. O_EXCL must fail and Stage cleanup,
   which has no owned target fd, must leave the file untouched.
4. Once Stage opened its own target fd but before copying any bytes,
   force a Stage failure. The exact same owned zero-length ciphertext
   may be unlinked, the empty directory removed and no candidate leaked.

## Limits and release holds

Same-UID adversarial directory-entry exchanges between identity checks
and unlinkat are still not protected by atomic compare-and-unlink on
ordinary Linux filesystems. The extra identity checks reduce accidental
or persistent mismatches but are NOT a proof against a continuously
racing non-cooperative same-UID actor. In ambiguous states preserving
possible ciphertext and refusing cleanup is mandatory.

Issue #59 intermittent `create_scope` refusal remains OPEN; these
security changes have not established its cause. Do not enable live
restore, candidate auto-GC, T15/T23/T20/T25 long-soak acceptance,
unlicensed CN offline resources or release. Preserve unprivileged
Linux/no TUN, original Karing five-layer routing without
subscription/ISP routing sources, approved native Core pin and stable
`main`.

Draft stacked on PR #89 (ADR 0209). Once #89 passes final exact-head
CI and merges into `feat/m0-m1-foundation`, integrate this latest
development baseline and retarget. Merge only when exact final head
ordinary Go CI, all four Race shards, Managed Core Integration and
native Linux amd64/arm64 Core Provenance pass.
