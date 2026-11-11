# ADR 0213 — Reuse the freshly verified child directory fd for Stage flock

Status: Draft internal M5 / T15-T23 candidate directory custody; stacked on
ADR 0212 / PR #92. No release or live-restore permission.

## Why

ADR 0212 captures an early `fstatat(AT_SYMLINK_NOFOLLOW)` device/inode
receipt after `mkdirat` and checks the descriptor from the FIRST
`openat` against it. However, Stage historically immediately closed that
first verified child descriptor and used
`openLockedInertRestoreCandidateAtParentProbed` to `openat` the exact
same name a SECOND time before acquiring the child `flock`.

The second opening adds an avoidable identity transition, kernel resource
churn and path-mutation opportunity in the same-UID/advisory-lock threat
model implicated by Issue #59. Stage's final pathname/inode checks could
reject a persistent replacement, but the second descriptor could refer to
the *replacement* until that later check. It also made the creation receipt
and the lease apply to different file descriptors.

## Decision and implementation

- Preserve `createInertScopeAtLeasedParent`,
  `createInertScopeAtLeasedParentProbed` and the preexisting independent
  `openLockedInertRestoreCandidateAtParentProbed` (Reopen/test use).
  The private `createInertScopeAtLeasedParentRetainedProbed` optionally
  transfers ownership of the same O_DIRECTORY|O_NOFOLLOW child fd after
  the ADR 0212 `fstatat` device/inode/UID receipt comparison. Direct
  callers still receive FileInfo, and close the short-lived fd.
- Stage alone uses the retained creation fd and calls private
  `lockCreatedInertRestoreCandidateAtParentProbed`. It verifies that
  the original fd still names the receipt inode, then acquires an
  exclusive nonblocking `flock` on that SAME fd, checks canonical child
  and parent pathname identities, and only then transfers fd ownership
  into `InertRestoreCandidate.dir`. Failed adoption never steals fd
  ownership; Stage closes it BEFORE trying guarded empty-scope cleanup.
- All existing private test checkpoints remain, including
  `scope_child_open`, `scope_child_fd_opened`,
  `scope_child_flock`, `scope_child_lock_held`,
  `scope_child_identity`, and `scope_child_identity_verified`.
  A new fixed test-only `scope_child_fd_reused` checkpoint shows the
  absence of a second openat for newly created Stage child scopes.
  Failures keep existing busy/unsafe sentinels. No raw paths, random
  names, errno text or secrets are sent to any public log or API.
- The original private parent flock remains short-lived, and its
  no-follow identity and fsync rules are unchanged. All encrypted
  Stage/Verify/Close/Reopen/explicit Discard paths retain prior
  authentication, owner and permission checks, and restore-disabled
  results. No automatic candidate retry or garbage collector is added.

## Deterministic Linux regression

- After creation and the early identity receipt, inject an in-directory
  replacement at the new pre-flock reuse checkpoint. Rename the original
  child elsewhere and replace its path with another UID-owned 0700
  directory carrying a sentinel. While Stage reports the child flock
  held, a separate descriptor opened on the RENAMED ORIGINAL must
  observe lock contention. Stage must still refuse the canonical path
  mismatch and never adopt or delete the foreign directory. After
  refusal, the original flock and parent reservation must be released.
- Normal real sealed encrypted Stage must publish a candidate whose
  `dir` inode equals the creation receipt and denies a competing flock.
  Full read-only Verify, Close, Reopen and requested Discard succeed;
  no `RestoreReady` or `RestoreSupported` permission is granted.
- A private injected child-adoption refusal must leave the retained
  file descriptor caller-owned until Stage closes it. The strict
  empty-scope cleanup must still remove only the original inode.

## Residual risks and gating

The very first post-mkdirat `fstatat` receipt remains non-atomic with
mkdirat, and same-UID processes can still mutate directory entries
between checks. This removes one *second openat* window but does not
prove an atomic mkdir+open+lock transaction or the root cause of Issue
#59's intermittent `create_scope` refusal. Retain the issue OPEN.

No real restore, automatic candidate GC, T15/T23/T20/T25 closure,
CN offline licensed resource redistribution, 72h/7d/30d acceptance
or production release. Linux unprivileged/no TUN, the original Karing
five-layer routing WITHOUT subscription/ISP route sources, approved
Core pin and stable `main` remain unchanged.

Stacked Draft on PR #92. After PR #92 merges, retarget and integrate
against `feat/m0-m1-foundation`, then require exact-final-head
ordinary Go CI, all four Race shards, Managed Core integration and
native Linux amd64/arm64 provenance before merge.
