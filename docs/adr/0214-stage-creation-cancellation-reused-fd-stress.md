# ADR 0214 — Bound cancelled Stage scope creation and stress the actual retained child fd path

Status: Draft M5 / Issue #59 reliability investigation, stacked on ADR 0213
(PR #93). No restore, automatic cleanup or release authorization.

## Problem and scope

ADR 0212 captures a post-mkdirat child device/inode receipt; ADR 0213
uses that first verified directory fd directly for the Stage child
flock, avoiding the earlier second openat. However the existing
512-cycle `TestInertCandidateScopeLeaseCyclesDoNotLeakOrGrantCompetingLease`
still exercises the older, independently reopened child helper, so it
**does not stress Stage's new retained-fd-to-flock path**. A green
ordinary test could miss repeated descriptor/lock leaks specific to the
production path implicated by intermittent Issue #59 `create_scope`
refusals.

Stage also accepts a cancellable context for the entire bounded
operation. When its deadline was reached at the `create_scope` or
`scope_before_mkdirat` test boundary, the old code could still allocate
a new scope and acquire a child flock before later ciphertext I/O
noticed cancellation. At `scope_created` or `scope_locked`, cancelled
work could proceed with unnecessary metadata/fsync activity. This is
not evidence of the historical Issue #59 root cause, but is an
avoidable allocation and cleanup risk under shutdown/cancellation.

## Decision

1. At the existing Stage `create_scope` and
   `scope_before_mkdirat` checkpoints, check `ctx.Err()` after the
   checkpoint callback and return the existing unsafe-candidate
   sentinel **before** invoking `mkdirat`. Production has no
   additional callback or retry.
2. At `scope_created`, check the same context after a verified
   creation receipt. If cancelled, close the exact still-owned child
   fd, then attempt ONLY the existing original-parent-fd/created-inode
   guarded empty-directory cleanup; never delete a foreign scope by
   pathname. At `scope_locked` check cancellation before parent
   fsync/lease publication, letting the existing strict
   `discardStageLocked(nil)` path release child flock and empty scope.
   Check cancellation before `cipher_copy` to prevent opening an
   unnecessary new ciphertext target. Preserve all other checkpoints.
3. Add a **separate** native Linux bounded 512-cycle test of the
   ACTUAL Stage retained-creator-fd + exclusive child flock functions,
   verifying creation receipt equals lock inode, competing contender
   receives Busy, Close/Reopen works, only the original empty scope
   is cleaned, parent lock can be reacquired, and /proc/self/fd count
   does not exhibit sustained growth beyond a small scheduler
   tolerance. Keep the legacy independent second-open stress test to
   separately exercise Reopen; do not substitute or suppress it.
4. Add real encrypted Stage cancellation fault injection at the
   pre-mkdirat, post-creation, post-fd-handoff, post-flock, scope
   publication, and pre-copy checkpoints. Each must yield no
   candidate, no lingering candidate scope/parent lock, unchanged
   original ciphertext, and the original public fail-closed error.
   The no-context-change happy path and all three independent
   encrypted preflight passes remain unchanged.

## Safety and limits

The user-facing Stage API and recovery-disabled receipt are unchanged;
no plaintext, automatic Stage retry, new filesystem cleanup authority
or secret-bearing diagnostics. A cancellation may occur BETWEEN
syscalls, so this is a bounded fail-closed admission/cleanup guard,
not an atomic cancellation barrier.

The targeted 512-cycle test and new phase coverage reduce a blind spot
in CI but do NOT identify or prove a root-cause fix for Issue #59.
Intermittent hardware/filesystem/kernel errors remain possible and
must be diagnosed from exact failure phases, not retried into green.

T15/T23 live restore, T20/T25 72h/7d/30d soak, automatic candidate GC,
CN offline resource license/distribution and release gates stay OPEN.
Preserve Linux ordinary user/no TUN, Karing five-layer routing excluding
subscription/ISP route sources, approved native Core pin and stable
`main`.

Keep this PR stacked on #93. After #93 passes its FINAL exact-head CI
and merges into `feat/m0-m1-foundation`, integrate/retarget here.
Merge only after ordinary Go CI, all four Race shards, Managed Core
Integration, and native linux-amd64/arm64 Core Provenance pass on the
FINAL integrated head.
