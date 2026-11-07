# ADR 0218 — Bound explicit Discard cancellation to the first irreversible unlink

Status: Draft M5 / T15-T23 manual encrypted candidate deletion safety.
Stacked on ADR 0217 (PR #97), which in turn depends on merged ADR 0216.
No restore or automatic candidate GC authorization.

## Gap

The explicit `InertRestoreCandidate.Discard(ctx)` checks `ctx.Err()` only
before calling the existing inode-guarded deletion helper. The helper can
inspect a valid ciphertext inode, pin the original 0700 parent and encrypted
leaf descriptors, and continue to `unlinkat` even if the operator cancels
during this read-only pre-unlink work. This unnecessarily ignores a
cancelled destructive request.

Conversely, after the ciphertext is already unlinked, returning early for
cancellation would strand an empty private candidate scope. There is no
safe way to restore the original ciphertext on the same inode, and a
half-finished deletion requires manual investigation. The completion
boundary must be explicit.

## Decision

- Preserve the public `Discard(ctx)`, `Stage`, `Verify`, `Reopen`,
  `Close` and all existing private test hook signatures. Only the
  **explicit** user-invoked Discard supplies its context to the new
  package-private `discardLockedWithLeafContextProbed` helper.
- The original `discardLockedWithLeafProbe` remains as a
  `context.Background()` wrapper. In particular, **failed Stage
  cleanup must not be interrupted by its cancelled original context**:
  it must still release the file descriptors, attempt only identity-safe
  cleanup of the inode Stage itself created, and never silently delete
  a foreign candidate.
- Once Discard has entered the actual deletion helper, check cancellation
  on entry, after the original parent descriptor is independently pinned,
  immediately after the test-only pre-ciphertext-unlink checkpoint, and
  immediately before `syscall.Unlinkat`. On cancellation before this first
  irreversible call, return the existing unsafe-candidate sentinel,
  preserve ciphertext and private child scope, and close only the active
  operation's candidate lease as in any existing failed Discard.
- **After successful ciphertext unlink**, do not consult cancellation
  again. Finish child `fsync`, original-parent inode/lease revalidation,
  exact empty child `unlinkat(AT_REMOVEDIR)`, parent `fsync` and normal
  descriptor closure. Existing checks still fail closed on a foreign
  inode, changed parent or unexpected sibling. Cancelling at this point
  cannot recreate the original ciphertext.
- Do not add public callbacks, secret-bearing errors, auto retry,
  deletion permission, automatic candidate scanning/GC or restore.

## Native Linux regression

1. Stage real encrypted candidate, cancel the explicit context at the
   existing private pre-ciphertext-unlink checkpoint AFTER parent and
   leaf leases have been acquired. Discard must refuse with the old
   unsafe sentinel, preserve the original encrypted file and directory
   inode/bytes, release the parent/child flock, and permit a healthy
   Reopen→Verify with both restore flags still false.
2. Cancel from the existing private checkpoint after the ciphertext
   unlink/child fsync but before empty-directory unlink. Discard must
   complete the exact original empty-scope removal, report success,
   release its locks and leave a clean parent directory. This is
   **completion of an already committed destructive operation**, not
   cancellation being ignored before it commits.
3. Pre-cancelled public Discard must preserve its existing `context.Canceled`
   return contract and must not close the caller-owned candidate flock.
   Later healthy Verify still works. Existing same-UID ciphertext/parent
   replacement tests, Stage-only custody checks and explicit healthy
   Discard regressions remain part of the full test matrix.

## Limits and gates

`ctx.Err()` and `unlinkat` cannot be an atomic transaction; a
cancellation between the last check and the syscall remains a residual
race. Nor are pathname identity checks atomic against a malicious
non-cooperative same-UID process. This change does NOT solve Issue #59
intermittent candidate `create_scope` failures and does NOT establish
T15/T23 recovery acceptance or T20/T25 72-hour/7-day/30-day soak.

Keep real restore and automatic candidate GC disabled, no stable release,
no unlicensed CN offline asset distribution, ordinary-user Linux/no TUN,
Karing's five routing layers excluding subscription/ISP routing sources,
the approved Core pin and unchanged stable `main`.

After PR #97 passes its **final integrated head** ordinary Go CI, Race
4/4, Managed Core Integration, and native amd64/arm64 Core Provenance,
merge #97 into `feat/m0-m1-foundation`, recreate this single ADR 0218
commit on the new base, and repeat the same exact-head matrix before
merging ADR 0218.
