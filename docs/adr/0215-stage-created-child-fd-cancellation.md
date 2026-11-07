# ADR 0215 — Propagate Stage cancellation into created child-fd flock admission

Status: Draft M5 / Issue #59 candidate lease reliability and fail-closed
shutdown safety. Stacked on ADR 0214 (PR #94).

## Gap

ADR 0213 reuses the original, independently verified `mkdirat`-created
child directory descriptor for Stage's exclusive `flock` and eliminates
the second mutable-path `openat`. ADR 0214 checks `ctx.Err()` at
`create_scope`, `scope_before_mkdirat`, `scope_created`,
`scope_locked` and `cipher_copy`. However, the private
`lockCreatedInertRestoreCandidateAtParentProbed` helper still takes no
context. If cancellation occurs during its `scope_child_fd_reused`,
`scope_child_fd_opened`, `scope_child_flock` or
`scope_child_lock_held` checkpoints, Stage might continue issuing
`flock` and path/parent inode checks before its later
`scope_locked` context gate notices the cancellation.

The original Stage caller always owns the created fd until successful
adoption. Avoiding those unnecessary syscalls on a cancelled operation
reduces lock/descriptor hold times without changing adoption authority,
crypto, or the behavior of independent Reopen.

## Decision

- Introduce only package-private
  `lockCreatedInertRestoreCandidateAtParentContextProbed(ctx, ...)`.
  Stage supplies its already bounded context. Preserve the existing
  `lockCreatedInertRestoreCandidateAtParentProbed(...)` signature
  for direct tests and existing callers by wrapping the new function
  with `context.Background()`.
- Check cancellation before any directory/FD admission operations,
  after each existing child-fd probe checkpoint, **immediately before
  flock**, after the lock-held checkpoint, and after the verified child
  and parent identity checks but before returning the candidate.
  A nil context is refused. The additional fixed private
  `scope_child_context_cancelled` probe label never includes paths,
  keys, metadata, caller-supplied errors or raw errno text.
- Cancellation returns the existing unsafe candidate sentinel. On any
  refusal the original created descriptor remains caller-owned; Stage
  closes it, thereby releasing any newly acquired flock, before the
  existing original-parent/original-child-inode guarded cleanup.
  Only fully checked, noncancelled paths transfer fd ownership to
  `InertRestoreCandidate.dir`. Do not reopen the path, introduce
  retries, unlink unknown directories or loosen original lock/UID/0700
  checks.
- Keep full sealed source HMAC, candidate SHA/inventory, memory SQLite
  verification, public Stage/Reopen/Verify/Discard interfaces, original
  Core pin and disabled restore flags intact.

## Native Linux regression

1. A genuine encrypted Stage cancelled synchronously at each existing
   original-child checkpoint (before reuse, after reuse, before flock,
   after flock, and after inode verification) must refuse BEFORE the
   next phase, emit the single private cancellation class, preserve
   ciphertext and leave no candidate scope or held parent flock.
2. Direct context-aware child admission with nil or pre-cancelled
   context must not touch the candidate flock or close the caller's
   original created descriptor. A separate contender may acquire a
   child flock; caller can close its descriptor and perform strict
   owner-verified empty-directory cleanup.
3. A cancellation combined with a same-UID test-only replacement of
   the original 0700 candidate scope by a different directory and
   sentinel must leave both original and substitute directories and
   the sentinel untouched, release parent and original child flocks,
   and never progress to the child `flock` syscall.

## Limits, dependency and release hold

`ctx.Err()` and each Linux syscall are separate operations: a
cancellation immediately after a check may still race the next
syscall. This is a bounded early refusal, **not** an atomic cancellation
barrier or evidence that Issue #59's intermittent create-scope
refusal has been diagnosed or fixed.

This change does not enable T15/T23 real restore, candidate auto-GC,
T20/T25 72h/7d/30d acceptance, CN offline licensed resources or
release. Preserve ordinary-user Linux/no TUN, Karing five-layer routing
without subscription/ISP rule source layers, approved native Core,
stable `main` and disabled RestoreReady/RestoreSupported.

Remain a Draft PR stacked on #94. After #94 passes its FINAL
exact-head CI and merges into `feat/m0-m1-foundation`, integrate
and retarget this PR; require ordinary Go CI, 4/4 Race shards,
Managed Core integration and native Linux amd64/arm64 Core Provenance
on the final exact integrated head before merging.
