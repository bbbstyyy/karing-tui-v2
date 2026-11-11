# ADR 0216 — Honor Reopen cancellation before and after independent child flock admission

Status: Draft M5 / T15-T23 encrypted candidate lease reliability, stacked on
ADR 0215 (PR #95). No restore or automatic GC authorization.

## Existing boundary

ADR 0213 reuses the original first-opened candidate child fd for **Stage**.
ADR 0214 rejects cancelled Stage before allocating a new child and stress
tests its retained-fd lifecycle. ADR 0215 propagates Stage cancellation
into its newly-created child fd/flock admission.

**Reopen is different**: it must independently obtain a NEW child fd after
Close or process death, then acquire its exclusive flock and run complete
HMAC, encrypted inventory and SQLite logical preflight. Its public
`ReopenInertRestoreCandidate(ctx, directory, key)` already accepts a
context, but `openLockedInertRestoreCandidateAtParentProbed` never receives
it. If the caller cancels after the parent inventory but before or during
child `openat`, `flock` or directory identity checks, Reopen may still
acquire and hold a no-longer-needed child lock, needlessly extending
contention and inode-check activity until full preflight sees the cancel.

This is a bounded resource-lifetime weakness, **not proof** of the
intermittent Issue #59 `create_scope` root cause.

## Decision

- Preserve the existing private
  `openLockedInertRestoreCandidateAtParentProbed(path, parent, probe)`
  signature used by Stage-independent tests and direct helpers, as
  a `context.Background()` wrapper for a new strictly private
  `openLockedInertRestoreCandidateAtParentContextProbed(ctx, ...)`.
  Reopen forwards the SAME caller-owned context to this new variant.
- Check ctx at helper entry, after its existing
  `scope_child_open`, `scope_child_fd_opened` and
  `scope_child_flock` checkpoints, immediately before the nonblocking
  `flock` syscall, after `scope_child_lock_held`, after
  `scope_child_identity_verified`, and just before ownership transfer.
  For nil/cancelled ctx return the existing unsafe-candidate sentinel;
  issue only the fixed, test-only `scope_reopen_context_cancelled`
  phase label. No absolute path, key, filename, errno text or secret
  leaves the private probe.
- Reopen owns any newly opened child fd. On cancellation after open or
  even after successful flock, CLOSE that fd before returning, thereby
  releasing its lock. It NEVER closes the caller-held original parent
  lease from inside the helper. The outer Reopen operation keeps its
  parent-lock lifecycle unchanged.
- Add explicit cancellation checks after the outer child-lease
  acquisition, after the private pre-HMAC checkpoint and after the
  full preflight callback. Cancellation never yields a successful
  candidate receipt, even if the full HMAC was healthy at the moment
  it completed. The existing deferred `candidate.Close` path
  releases the borrowed candidate lease.
- Keep the existing public Reopen/Stage/Verify/Discard APIs,
  all HMAC/SHA/resource/SQLite checks, UID/0700/flock/parent inode
  checks, disabled RestoreReady/RestoreSupported flags and Core pin
  unchanged. No retry, new cleanup authority, plaintext or live Core
  mutation is introduced.

## Deterministic Linux regressions

1. Stage a genuine authenticated encrypted candidate, Close it, then
   cancel context at each independent child `open`, fd-opened, pre-flock,
   post-flock and identity-verified probe. The next phase must not run.
   Each refusal must close the new child fd and release any flock; a
   separate contender must acquire the candidate lock successfully.
   Both the encrypted bytes and original child inode remain intact.
2. A nil or already-cancelled context must refuse before opening a
   child fd and leave the caller-owned parent directory lease open.
3. Reopen-level cancellation after parent inventory/before child open,
   before full HMAC, and after successful full preflight must refuse
   and release parent and child locks without changing ciphertext.
   A healthy subsequent Reopen/Verify still succeeds read-only.
4. If another same-UID process substitutes an equally private but
   unrelated child scope and sentinel at the private pre-child-open
   boundary while the context is cancelled, Reopen must refuse
   without adopting, deleting or modifying either scope.

## Limitations and merge condition

Context checks and Linux system calls are not atomic. Cancellation
immediately after a check may still race one openat or flock, but the
next check and fd close must fail closed. Directory flock is advisory:
this does not establish isolation from actively hostile same-UID
processes or prove Issue #59 fixed.

No T15/T23 live restore, auto candidate GC, T20/T25 72h/7d/30d soak,
licensed offline CN rules, official release or automatic retry.
Preserve ordinary user Linux/no TUN, original Karing five-layer
routing excluding subscription/ISP rule source layers, approved
Core pin and stable main.

Stacked Draft on PR #95. After #95 passes final exact-head CI and
merges into feat/m0-m1-foundation, integrate/retarget this PR and
revalidate the FINAL head's ordinary Go CI, Race 4/4, Managed Core
integration and native Linux amd64/arm64 Core Provenance.
