# ADR 0184 — Deterministic candidate scope lease and identity regressions

Status: implementation pending exact-head CI (Issue #59, T15/T23 partial).

## Context

ADR 0182 and ADR 0183 record bounded, non-sensitive admission and syscall
failure stages for the intermittently refused encrypted restore candidate.
The last known failing Race fixture stopped at `create_scope`, with a clean
independent archive/SQLite preflight and sufficient disk space. The exact
root cause remains unknown: the successful subsequent CI cannot prove the
system no longer fails under descriptor pressure or scheduling variation.

## Decision

Add bounded Linux-only tests, without changing the production restore code:

1. Run 128 sequential private child-scope creations under the locked parent.
   For every new child, acquire an exclusive directory flock and demand a
   second independently opened fd be refused with the busy sentinel.
   Close and reacquire the lease, then remove only that exact empty scope.
   Verify the parent contains no retained children after all cycles.
2. At the test-only `scope_child_lock_held` checkpoint, deterministically
   replace the pathname with a distinct private directory inode, replace it
   with a symlink, or weaken permissions. The already opened/locked fd must
   never authorize the new path; all cases fail with the existing unsafe
   sentinel and do not return an adoptable candidate.
3. Check lock-contention failure classification continues using a fixed
   non-sensitive label.

These tests exercise descriptor reuse, flock exclusion, inode identity
and pathname race refusal without repeatedly decrypting real credentials.
No real restore, rewrite of a live DB, background retry, candidate
garbage collection, broadened error details, or privileged change occurs.

## Acceptance and remaining uncertainty

This is a targeted T15/T23 Linux lock correctness regression, not a root
cause fix for the intermittent CI staging failure. Issue #59 remains open
until causal evidence exists. Do not promote any release gate or mark T23
complete solely because the test passes. Require exact-head ordinary CI,
Go Race 4/4, Managed Core, native amd64 and arm64 verification before
merge; preserve stable `main`, no TUN and no subscription/ISP routing.
