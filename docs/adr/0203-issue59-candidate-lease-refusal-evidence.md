# ADR 0203 — Diagnose intermittent candidate lease refusals without relaxing fail-closed checks

Status: test-only and private probe instrumentation; **not** a root-cause fix (M5 T15/T23 / Issue #59).

## New CI evidence

PR #82 exact head `6d27a2075cb5277822a758eb2ac33797ecb2d3b9`
ordinary CI run `41574188362` failed on Linux in
`TestInertCandidateScopeLeaseCyclesDoNotLeakOrGrantCompetingLease`
at cycle **93** with the constant `ErrUnsafeInertRestoreCandidate`
when opening the child candidate lease. Managed Core Integration and
native linux-amd64/linux-arm64 succeeded; the Race shards were
skipped after the ordinary test failure.

This resembles Issue #59's intermittent `create_scope` admission
refusals, but the test failure did not expose the failing syscall
or inode check. A retry alone would be insufficient to claim a fix.

## Decision

- Expand the existing *test-only* empty candidate scope/child flock
  stress loop from 128 to 512 bounded iterations. It must still
  perform real parent flock acquisition, fresh private scope
  creation, original child lease admission, competing lease
  rejection, release/reacquisition and exact empty-scope removal.
- Use the existing package-private probe callback on the initial
  child lease open. On an **unexpected failure only**, report
  bounded fixed checkpoint names, existing classified syscall
  failure labels, the integer `/proc/self/fd` entry count and
  process soft fd limit, and boolean scope/parent fd/path/mode
  checks. Never include paths, directory names, file content,
  keys, raw OS errors or plaintext in these new diagnostics.
- Add `scope_child_parent_identity_refused` to the private
  child-admission probe immediately before denying a newly
  opened child because its parent inode changed. The production
  API remains `openLockedInertRestoreCandidate`, which always
  passes a nil probe; error sentinels and rejection conditions
  are unchanged.
- Add a deterministic Linux proof: after the child's flock and
  inode check, rename the original parent, recreate another
  owner-private parent at the canonical path, and move the
  **same original child inode** there. Admission must fail closed,
  emit the fixed parent-identity refusal label and preserve the
  original child directory.

## Acceptance and unresolved risks

This change improves causal observability but does **not**
establish Issue #59's root cause or eliminate it. If another
failure occurs, diagnose the specific reported fixed phase and
fd/identity facts and implement a *separate* causal regression
and fix. Do not add retries or weaken UID/0700, flock, inode,
ciphertext, SQLite or HMAC admission. No production log
contains private archive paths or credentials.

Issue #59 remains open, T15/T23 real restore and candidate
auto-GC stay disabled, and T20/T25 long-running tests and
official release gates remain unfulfilled. Preserve Linux
without TUN, Karing's five-layer routing excluding
subscription/ISP source rules, offline CN license holds,
approved native Core and unchanged stable `main`.

Do not merge before the dependencies ADR 0201/0202 and the
final exact-head ordinary CI, Go Race 4/4, Managed Core,
linux-amd64 and linux-arm64 Core Provenance are all green.
