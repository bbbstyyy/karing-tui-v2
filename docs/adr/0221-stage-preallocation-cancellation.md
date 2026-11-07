# ADR 0221 — Stop cancelled Stage before source, disk and parent-inventory work

Status: Draft M5 candidate admission reliability and resource lifetime.
Stacked on ADR 0220 (PR #100). No actual restore, automatic candidate
garbage collection or release authorization.

## Gap

ADR 0214 refuses context cancellation before mkdirat, ADR 0215 does so
during the newly created child-fd flock handoff, and ADR 0219 covers the
post-copy fsync/HMAC/receipt path. Before child allocation, Stage has
five older private checkpoints whose callbacks may return true **after**
synchronously cancelling the context:

- `source_preflight`, before pinning the source parent and cipher fd.
- `source_inode_pinned`, after pinning the exact source parent/cipher fd
  but before the initial full HMAC/SQLite preflight.
- `disk_reserve`, before the disk capacity check.
- `parent_lock`, before the candidate-parent exclusive flock attempt.
- `parent_inventory`, after obtaining that flock but before opening a
  separate directory inventory stream.

Those checkpoints previously gated only on the probe's bool, not the
subsequent `ctx.Err()`. Lower layers often reject a cancelled request,
but Stage could still consume descriptors, perform a filesystem syscall
or retain its parent flock unnecessarily before the next context-aware
gate. A cancelled Stage must stop at the earliest known boundary and must
not create an encrypted candidate.

## Decision

- Keep public Stage/Reopen/Verify/Discard/Close interfaces, the existing
  private `stageInertRestoreCandidate` probe signature, HMAC/SHA,
  SQLite/schema checks, archive and rule formats, Core pins, and existing
  fail-closed errors unchanged.
- Add `ctx.Err()` gates immediately after each of the five checkpoints
  listed above. For cancelled contexts return only the pre-existing
  `ErrUnsafeInertRestoreCandidate` sentinel. Do not probe later phases,
  attempt unnecessary disk reservation/parent flock/parent inventory, or
  allocate a new candidate directory after the cancellation.
- The source parent and cipher fds remain closed by their established
  defers. A parent lock already obtained before `parent_inventory` is
  released by the existing short scoped defer. No new public debug logs,
  retries, override permissions, untrusted path deletion or new
  destructive cleanup is introduced.
- This is a bounded cancellation/descriptor-lifetime improvement, not
  a proof of atomic cancellation with syscalls or a diagnosis of
  Issue #59's historical intermittent `create_scope` refusal.

## Native Linux regression

1. Stage a real authenticated encrypted source and synchronously cancel
   at each of the five fixed phase labels while returning true from
   the private callback. Require the injected phase to be the LAST
   observed phase, no returned candidate, the existing unsafe sentinel,
   unchanged original ciphertext, empty candidate parent, and a parent
   flock reacquirable by another operation.
2. A later successful Stage→Verify→explicit Discard must work and keep
   `RestoreReady=false` and `RestoreSupported=false`.
3. After the parent flock is acquired, have a non-cooperative same-UID
   test actor rename the original 0700 parent and replace its former
   pathname with a different 0700 parent containing a sentinel. Cancel
   at `parent_inventory`. Neither parent inode or sentinel may be
   modified, and the original moved parent's exclusive flock must be
   released.
4. Run 32 real Stage cancellations alternating between the source-fd
   and parent-flock phases, compare Linux /proc fd counts with a
   bounded margin, and require zero scope or parent lock residue.
   This is a short test, never a substitute for T20/T25 soak.

## Restrictions and integration

Issue #59 remains open pending a reproduced, classified staging refusal
and deterministic root-cause regression; do not claim this cancellation
patch resolves it. Real restore, automatic candidate GC, T15/T23
guest restore, T20/T25 72h/7d/30d long soak, CN offline redistribution
without complete licensing, and stable release remain blocked.
Keep ordinary-user Linux/no TUN, original Karing five-layer routing
excluding subscription/ISP rule sources, approved Core pin and stable
`main` unchanged.

PR #100 (ADR 0220) must first pass ordinary Go CI, four Race shards,
Managed Core and native Linux amd64/arm64 provenance on its final
integrated head and merge into `feat/m0-m1-foundation`. Recreate the
ADR 0221 change on that development head and repeat the same complete
exact-head CI matrix before merging this change.
