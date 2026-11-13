# ADR 0220 — Fail closed when Reopen is cancelled after final ciphertext identity inspection

Status: Draft M5 / Issue #59 restore candidate lease safety. Stacked on ADR 0219
(PR #99). No true restore, automatic candidate GC, or release authorization.

## Gap

ADR 0216 propagates Reopen's bounded context into an independently acquired
child openat/flock and checks cancellation before and after complete HMAC,
encrypted resource and SQLite preflight. ADR 0217 handles the separate
read-only Verify operation without releasing the caller-owned flock.
ADR 0219 adds a final receipt cancellation gate for Stage.

However, `reopenInertRestoreCandidateAtFileProbed` can still run
`inspectInertCandidateFile` after its post-preflight context check and
then publish `candidate.receipt` without another `ctx.Err()` check.
A cancellation arriving during final inventory or inode comparison can
thus yield a successful candidate lease after a request is already
cancelled. Unlike Verify, **Reopen owns** its newly opened child flock and
must release it when this operation refuses.

## Decision

- Retain the public `ReopenInertRestoreCandidate`, Stage, Verify, Close
  and explicit Discard APIs and the old package-private
  `reopenInertRestoreCandidateAtFileProbed` signature used by earlier
  tests.
- Introduce one package-private
  `reopenInertRestoreCandidateAtFinalIdentityProbed` that forwards the
  existing pre-child-open, pre-HMAC and post-preflight hooks plus an
  optional **after-final-identity** test checkpoint. Production and
  all older helpers pass nil for the new checkpoint. It runs only after
  the original child inode, ciphertext inode, size and mtime are
  rechecked successfully, before publishing the receipt.
- Check `ctx.Err()` after that checkpoint and immediately before
  `candidate.receipt` is assigned. A cancelled request returns nil
  candidate and the existing `ErrUnsafeInertRestoreCandidate`
  sentinel, not a stale authenticated receipt. The existing named
  return + deferred failure `candidate.Close` releases Reopen's
  **newly acquired** child flock; the original short-lived parent
  reservation lock remains owned and closed by its separate block.
- Preserve all original HMAC/SHA/resource/SQLite/schema verification,
  current UID/0700/0600/single-hard-link and inode identity admission,
  authorized Core pin and disabled RestoreReady/RestoreSupported
  receipts. No new public callback, secret-bearing log, automatic
  retry, data deletion or candidate restore permission.

## Deterministic native Linux regression

1. Stage real authenticated encrypted ciphertext, close the original
   candidate lease, then reopen via the private final-identity
   checkpoint and cancel the context. Require a nil candidate and unsafe
   sentinel, with exact original ciphertext inode and bytes and child
   directory inode preserved. Independent child and parent flocks must
   be reacquirable. A normal subsequent Reopen→Verify must pass and
   both restore flags remain false.
2. After successful final inspection, inject synchronous cancellation
   together with a same-UID move of the original ciphertext inode and
   replacement by a distinct byte-for-byte identical valid encrypted
   inode, plus a sentinel. No candidate may be adopted; both original
   and foreign ciphertext and the sentinel must survive; no locks
   remain held. Independent read-only Preflight can verify the foreign
   file to prove refusal is from cancellation rather than bad HMAC.
3. Prior Reopen before-child-open/pre-HMAC/post-HMAC cancellation,
   foreign-scope refusal and healthy Stage/Verify/Discard regressions
   remain intact.

## Limits and integration gates

The final `ctx.Err()` check and return are not atomic with future
cancellation; this is a bounded observed cancellation guarantee, not
an atomic revocable credential. A continuously racing non-cooperating
same-UID process can still exchange directory entries between
independent syscalls; the lock is advisory. This change does **not**
diagnose Issue #59 intermittent `create_scope` staging refusal.

True restore and automatic candidate GC stay disabled. No T15/T23
guest restore acceptance, T20/T25 72-hour/7-day/30-day soak acceptance,
unlicensed CN offline-rule redistribution or stable release. Keep
unprivileged Linux/no TUN, the original Karing five routing layers
excluding subscription/ISP rule sources, approved Core pin and stable
`main` unchanged.

After PR #99 passes final-head ordinary Go CI, four Race shards, Managed
Core integration and native Linux amd64/arm64 provenance and merges into
`feat/m0-m1-foundation`, recreate the ADR 0220 change on that exact
development head. Merge this PR only after the same full matrix passes
on **its own final integrated head**, not a stacked test SHA.
