# ADR 0191 — Bind candidate child lease opens to the locked parent inode

Status: draft, exact-head CI required (M5 T15/T23 partial).

## Context

ADR 0190 creates encrypted restore candidate scopes with `mkdirat` on
an owner-private parent directory held under an exclusive flock. The
subsequent child lease still used `syscall.Open(candidate.directory)`,
which re-resolved the entire pathname. Reopen likewise scanned the
locked parent fd but then reopened the child from an absolute path.

The parent flock is advisory. A same-UID actor that ignores the lock
can rename the parent and replace its original pathname with another
private 0700 directory containing an identically named child. A valid,
copied ciphertext could pass full authentication even though it was
not the child discovered under the parent whose inventory was scanned.

## Decision

- In both Stage and Reopen, open the child directory with
  `openat(parent_flock_fd, child_name, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`.
  Do not fall back to an absolute-path child open if the parent fd is
  unavailable, invalid, or has a mismatched canonical identity.
- Preserve the exclusive child flock, full child fd/path inode checks,
  0700 privacy, and post-open parent fd/path identity recheck. The
  parent lock remains held through inventory and child acquisition.
- Keep the older path-opening helper for isolated internal lease tests,
  without using it for Stage/Reopen admission.
- Introduce a **private test-only** Reopen checkpoint after parent
  inventory and before child lease open. No public callbacks, runtime
  compatibility toggles, or error diagnostics are exposed.

## Regression evidence

1. During Stage, inject a parent rename at the child-open boundary,
   replace its path with a different private parent containing a
   same-name foreign child held under a conflicting flock. Stage must
   still obtain a child flock on the original leased parent's inode
   before refusing the pathname mismatch. It must never write to or
   delete the foreign child or original archive.
2. During Reopen, swap the parent after its one-child inventory with a
   second 0700 parent holding a same-name, 0600 copy of the **valid
   encrypted ciphertext**. Reopen must fail closed instead of adopting
   the cryptographically valid but wrong-parent candidate. Both
   ciphertext copies must remain unchanged.
3. Existing lease, discard, encrypted preflight and phase tests must
   remain green for unmodified paths.

## Scope and limitations

The post-open parent and child pathname checks are observations,
not atomic compare-and-unlink operations. An uncooperative same-UID
actor can still race later pathname accesses, and the multi-pass
authenticated archive preflight still opens by path. This PR does not
resolve Issue #59's intermittent `create_scope` refusal or enable
actual restoration, candidate GC, T15/T23 closure, T20/T25 soak,
CN resource redistribution, or production release.

Linux ordinary-user operation, no TUN, no subscription/ISP routing,
the approved Core, and stable `main` remain unchanged. Merge only
after exact-head ordinary CI, Go Race 4/4, Managed Core Integration,
and native Linux amd64/arm64 Core Provenance all pass.
