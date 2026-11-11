# ADR 0219 — Honor Stage cancellation after ciphertext copy and before candidate receipt

Status: Draft M5 / T15-T23 encrypted candidate staging reliability, stacked on
ADR 0218 (PR #98). No live restore or automated candidate GC authority.

## Remaining Stage admission gap

ADR 0214 refuses cancelled work before Stage creates a candidate child
directory. ADR 0215 propagates cancellation into the original created-child
fd/flock handoff. ADR 0216 and ADR 0217 harden independent Reopen and
read-only Verify. ADR 0218 bounds explicit Discard's cancellation to its
first irreversible unlink while keeping already-started safe cleanup
uninterruptible.

Stage's **post-copy** path has a separate gap. After it writes the exact
O_EXCL-owned authenticated ciphertext inode, it runs child fsync, parent
fsync, final full HMAC/SQLite/schema preflight, a final directory inode
check, and publishes an inert candidate receipt. Existing private
`scope_sync`, `parent_sync` and `candidate_revalidation` checkpoints
reject only a probe returning false, not a context cancelled by a
successful (true-returning) checkpoint. More importantly, after the
final authenticated preflight there is no fresh cancellation check before
returning a candidate.

The already-pinned child flock and O_EXCL-created target inode must be
owned until failure cleanup finishes; cancellation must not publish a
candidate merely because the final hash and schema checks succeeded.

## Decision

- Preserve public `StageInertRestoreCandidate`, `Verify`, `Reopen`,
  `Discard`, `Close` signatures, existing encrypted formats, errors,
  key policy, and the exact original target inode cleanup guards.
- Immediately after the existing `scope_sync`, `parent_sync`, and
  `candidate_revalidation` checkpoints, check `ctx.Err()` before
  proceeding with further fsync or final authenticated reads. Refuse
  with the existing `ErrUnsafeInertRestoreCandidate` sentinel.
- Add **only package-private test phase labels**
  `candidate_authenticated` (after successful full final HMAC/SQLite
  evidence comparison) and `candidate_receipt` (after final child/parent
  identity verification, immediately before the success receipt transfer).
  A probe returning false or an already-cancelled context fails closed.
- Reuse existing deferred Stage cleanup, which closes the exact locked
  child descriptor and can remove only the encrypted inode originally
  created with O_EXCL, checked by pinned fd identity. Do not retry
  automatically, delete an unknown replacement or change the original
  parent locking/durability behavior.
- No cancel check can be atomic with final candidate return. This change
  reduces the observable stale-cancellation window without claiming
  absolute cancellation/revocation guarantees.

## Deterministic native Linux regressions

- Stage a real authenticated encrypted archive and cancel via a
  **true-returning** private checkpoint at each of `scope_sync`,
  `parent_sync`, `candidate_revalidation`, `candidate_authenticated`
  and `candidate_receipt`. Require no candidate, the old unsafe sentinel,
  an empty original candidate parent, original ciphertext unchanged and
  parent flock releasable. A later healthy Stage→Verify→explicit
  Discard still works and both restore flags remain false.
- Update the existing all-private-stage-probe refusal matrix with the
  two new phases, and change its healthy last-phase assertion from
  `candidate_revalidation` to `candidate_receipt`. False-returning
  probes at those two boundaries must also fail closed.
- After final authentication, synchronously combine cancellation with
  same-UID substitution of a distinct, byte-identical encrypted candidate
  inode under the same name. Stage must never delete the foreign inode,
  its original moved inode or unrelated sentinel. Verify original and
  foreign ciphertext remain identical and both leases are released.

## Limitations and merge policy

This does NOT diagnose Issue #59's intermittent `create_scope` refusal;
the provenance/lease checks and cancellation checks cannot be atomic
against a non-cooperating same-UID actor. It does not authorize real
restore, candidate auto-GC, T15/T23/T20/T25 72-hour/7-day/30-day soak
acceptance, licensed CN offline redistribution or stable release.

Keep ordinary-user Linux/no TUN, Karing five-layer routing without
subscription/ISP routing sources, approved Core pin and unchanged
stable `main`.

PR #98 must pass ordinary CI, four race shards, Managed Core Integration
and native Linux amd64/arm64 Provenance on its exact integrated head,
then merge to `feat/m0-m1-foundation`. Only then recreate this change
on the new development head and run the same full exact-head suite before
merging ADR 0219.
