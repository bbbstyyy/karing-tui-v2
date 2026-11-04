# ADR 0209 — Bind candidate Reopen/Verify first HMAC to the inspected encrypted leaf inode

Status: Draft M5 T15/T23 inert-candidate safety; stacked on ADR 0208.

## Gap

ADR 0206 makes candidate Stage final verification, Reopen and active Verify
borrow the already flocked 0700 child directory fd; ADR 0207 retains the
first authenticated ciphertext leaf fd throughout three independent reads.
ADR 0208 makes Stage's SOURCE preflight compare the first HMAC read with
the source file fd pinned before Stage.

A corresponding boundary remains in Reopen and active Verify:
`inspectInertCandidateFile` validates the exact encrypted candidate leaf
and then **closes the read fd** before a separate full preflight. That
preflight can independently `openat` a different file inode under the
same locked parent, including a distinct 0600 file with byte-identical
valid ciphertext, if another process with the same UID ignores advisory
flocks. Final inspection can reject persistent drift, but cannot stop the
first HMAC from selecting a different file inode.

## Decision

- Introduce strict internal `pinInspectedInertCandidateCipher`. After
  existing locked-directory inventory, it opens a separate read-only,
  no-follow, fd-relative encrypted file, requiring it to have the SAME
  inode, mode, size and modification time as the inspected leaf, with
  UID/0600/single-link, original locked directory inode and original
  parent identity checks. On any refusal, the new fd is closed without
  modifying or deleting candidate bytes. The caller owns the returned fd.
- Reopen and active Verify retain this source fd until their full
  three-pass HMAC, full encrypted inventory and full encrypted SQLite
  validation and final metadata check are complete, passing it as the
  `expectedFile` argument introduced in ADR 0208. This requires the
  first HMAC read to match the previously inspected inode **before any
  ciphertext bytes are read**, and continues to check that inode after
  successful cryptographic and in-memory SQLite audits.
- Add nil-in-production private checkpoints to Reopen/Verify between
  the source file pin and initial HMAC for deterministic Linux tests.
  Preserve existing public signatures, existing private regression hooks,
  failure sentinels, receipt shape, ownership of directory flock and all
  cryptographic/SQLite requirements. No state write, archive mutation,
  retry, candidate discard/GC or restore permission is introduced.
- Stage's FIRST SOURCE preflight already uses ADR 0208. Stage's
  *final newly-created candidate* and its cleanup have separate
  custody/irreversible-unlink requirements; this change does not
  claim to solve same-UID races in that lifecycle.

## Deterministic Linux acceptance

1. With a real encrypted candidate, verify healthy Stage, active Verify,
   Close, Reopen, Verify and independent read-only report equivalence.
   Borrowed file descriptor stays caller-owned and read offset unchanged.
   RestoreReady/RestoreSupported remain false.
2. On the Reopen and Verify test-only boundaries after opening the
   inspected exact file fd but before initial HMAC, move that original
   ciphertext leaf out of the locked candidate and replace it in the
   SAME 0700 parent with a distinct inode containing byte-identical
   authenticated ciphertext. Both must refuse with the existing
   candidate sentinel, preserving original, substitute and sentinel.
   A separate standalone Preflight of the substitute still succeeds,
   demonstrating an inode-custody refusal, not an invalid archive.
3. Replacing the leaf after initial metadata inspection but before
   `pinInspectedInertCandidateCipher` must refuse even when the
   replacement is otherwise a valid encrypted archive. Failed admission
   must not close the caller's held flock fd or remove foreign bytes.

## Unresolved limitations and merge gate

Inode/path checks are not atomic against noncooperative same-UID processes
that change directory entries between checks. A new Reopen after Close
naturally establishes a new directory/file custody baseline; it is not
a persistent cross-restart inode authorization token. This change is
read-only: no transactional live restore or automatic candidate GC.

Issue #59 intermittent `create_scope` remains open and has no proved
causal fix. T15/T23 real restore, T20/T25 long-soak, offline CN rule
resource licensing and release gates remain closed. Preserve Linux
ordinary user/no TUN, Karing five-layer routing with subscription/ISP
route sources excluded, approved native Core pin, stable `main`.

Draft depends on PR #88 (ADR 0208). After it passes final exact-head CI
and merges, integrate/retarget this PR to `feat/m0-m1-foundation` and
revalidate exact final head: ordinary CI, all four Race shards,
Managed Core Integration, and native Linux amd64/arm64 Core Provenance.
