# ADR 0217 — Fail closed on Verify cancellation without surrendering the existing candidate lease

Status: Draft M5 / T15-T23 encrypted candidate verification hardening; depends on
ADR 0216 (PR #96) and its exact-final-head CI. No restore or candidate GC
authorization.

## Remaining read-only verification gap

ADR 0215 propagates cancellation into Stage's retained created-child flock
admission. ADR 0216 does so for Reopen's independently opened child flock,
and checks cancellation around Reopen's full preflight. By contrast,
`InertRestoreCandidate.Verify(ctx, key)` **borrows an existing locked child
directory** and reruns complete ciphertext HMAC, resource, SQLite and schema
checks. It previously rejected nil context but did not check an already
cancelled context before its initial child inventory and fresh leaf-fd pin.
It also returned a full successful report after the final inode inspection
without checking whether cancellation had arrived **after** preflight.

This is different from Reopen: a failed Verify must not close the caller's
existing candidate lease. Closing that flock would allow another reader or
actor to acquire it while the original caller still believes it owns it.

## Decision

- Keep the public `Verify`, `Close`, `Reopen`, `Discard` and archive
  preflight APIs unchanged, including the existing error sentinel
  `ErrUnsafeInertRestoreCandidate`. The earlier
  `verifyInertRestoreCandidateProbed(ctx, key, beforePreflight)` test helper
  remains a wrapper with its original signature and behavior.
- Introduce only package-private
  `verifyInertRestoreCandidateCancellationProbed` with nil-in-production
  checkpoints before inventory, before HMAC, after authenticated preflight
  and after final inode inspection. All callbacks are test-only and run
  while the existing candidate mutex is held; they do not add public
  diagnostics, network requests, automatic retries or filesystem mutation.
- Check `ctx.Err()` after the existing candidate-lock ownership check,
  after the pre-inventory and pre-HMAC checkpoints, after full preflight,
  and immediately before publishing the successful receipt. A cancelled
  request always returns a zero preflight and the existing unsafe sentinel,
  **even if all authentication just succeeded**.
- Keep the independently pinned read-only ciphertext fd scoped to the
  operation and close it on every return. Never close or change the
  caller-owned directory flock on Verify failure. Retain the original
  ciphertext inode, HMAC/SHA/SQLite/schema checks, receipt comparison and
  post-HMAC final inode inspection without introducing a restore action.

## Linux regression and acceptance

Use a real encrypted Stage candidate. Inject synchronous cancellation at
each of the four private checkpoints, including immediately after a
successful full preflight and after the final identity comparison. Require
zero returned evidence, unsafe sentinel, unchanged ciphertext and directory
inode, and a still-busy competing independent flock. A subsequent Verify
on the **same existing candidate lease** must succeed and report both
`RestoreReady=false` and `RestoreSupported=false`.

Nil context, pre-cancelled context and empty key must refuse before the
first inventory checkpoint without touching the existing lease; healthy
Verify after those refusals must still succeed.

## Limits and release hold

Context cancellation and the final return are not atomic. A cancellation
arriving after the last check can race the return. This improvement
bounds stale receipt publication at observable checkpoints; it is **not**
an atomic revocation mechanism, a long-running soak, or a diagnosis of
Issue #59's intermittent `create_scope` refusal. It does not make
Restore/automatic candidate GC safe or authorize T15/T23/T20/T25,
a redistribution-licensed offline CN bundle, or stable release.

Maintain unprivileged Linux/no TUN, Karing's five routing layers without
subscription/ISP rule sources, the approved Core pin and untouched
stable `main`. Merge only after prerequisite PR #96 passes ordinary Go CI,
4/4 race, Managed Core and native Linux amd64/arm64 provenance on its
final SHA and is merged. Then retarget this PR to the development base
and rerun those same exact-head checks before merging.
