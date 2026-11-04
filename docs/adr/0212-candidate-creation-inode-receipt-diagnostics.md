# ADR 0212 — Capture candidate scope inode receipt between mkdirat and openat

Status: Draft M5, Issue #59 create-scope attribution and narrow inode-admission safety.
Dependency: ADR 0211 (PR #91).

## Evidence and remaining gap

Issue #59 records intermittent candidate Stage `create_scope`/child-lease
refusals in GitHub Actions, including cycle 93 of a repeated scope/lease
test. Their exact syscall and underlying cause have **not** been proven.
The private test probe currently records an overall `scope_mkdir` failure,
but the `createInertScopeAtLeasedParent` implementation groups several
operations together: parent fd inspection, random name generation,
`mkdirat`, `openat` of the created child, `fstat`, `close`, and
mode/ownership validation. Any failure after `mkdirat` loses its
individual phase in the parent Stage error.

There is also a narrow security window: Stage captures its
`created` directory identity from the child descriptor opened *after*
`mkdirat`. An uncooperative same-UID actor can replace the name with a
different, equally private 0700 directory between the syscalls, so
`openat` can return a foreign inode. The later check compares to that
already-replaced descriptor, not to an earlier creation-side receipt.

## Decision

1. Preserve the existing `createInertScopeAtLeasedParent` signature and
   add a package-private `createInertScopeAtLeasedParentProbed`; the
   public Stage path forwards its already existing private test-only
   probe. Production calls with nil probe and has no new public API,
   log event, file path, random name or raw errno disclosure.
2. Immediately after successful `mkdirat`, capture a no-follow
   `unix.Fstatat(parent_fd, name, AT_SYMLINK_NOFOLLOW)` receipt
   with device number, inode, directory type, current UID and 0700
   mode. When the separately opened child directory fd is `fstat`ed,
   verify its device number/inode/UID against this earlier receipt.
   A replacement after the receipt must NOT become the candidate.
3. Distinguish fixed, private failure labels for parent path/fstat/
   mode/owner, random generation, mkdirat, the created-child fstatat,
   post-receipt openat/fstat/close, private mode and receipt-inode
   mismatch. Errno-derived labels use only existing bounded classes,
   adding `not_directory` for ENOTDIR. The 96-bit unpredictable
   candidate name, path, key and actual raw errno text never appear
   in these labels. Retry remains strictly limited to genuine
   mkdirat EEXIST collisions (eight attempts); no general Stage
   retries and no weakening of fail-closed production errors.
4. If parent/child identity is ambiguous or an uncooperative actor
   has already replaced the directory, return the same unsafe
   candidate sentinel. Do not delete a foreign child merely because
   its path occupies a previously created name; release local fds.
   The existing original parent flock and all later custody
   checks remain in place.

## Native Linux deterministic regressions

- After the fstatat receipt but before openat, rename the originally
  created empty 0700 scope aside and replace its old name with another
  0700 owned directory carrying a sentinel. The creator must reject
  with `scope_created_inode_changed`, and preserve both distinct
  directories and the sentinel; original parent flock remains valid.
- After successful mkdirat but before the fstatat receipt, remove
  the just-created empty child. The helper must report the fixed
  `scope_created_fstatat_failed_missing_path` class, refuse safely,
  and leave no candidate scope behind.
- Exercise the genuine encrypted Stage entrypoint with a private
  post-receipt replacement and verify it fails closed without adopting
  or deleting the foreign 0700 directory.

## Non-goals and gate

`mkdirat`, `fstatat`, and `openat` are **three distinct syscalls**.
A hostile same-UID actor can still swap an entry before the first
fstatat receipt or between later checks. This is not an atomic
create-and-open primitive or a proven root-cause fix for Issue #59.
The diagnostic labels are available only to in-package test probes;
no user-facing retry or relaxation is introduced.

Do not claim T15/T23 real restore, automatic candidate GC, T20/T25
long-soak acceptance, licensed offline CN resources or release.
Keep unprivileged Linux/no TUN, Karing five-layer routing excluding
subscription/ISP source layers, approved native Core and stable
`main` unchanged.

Remain a Draft PR stacked on #91 until it merges. Then integrate its
exact dev head, retarget to `feat/m0-m1-foundation`, and require full
ordinary Go CI, all four Race shards, Managed Core integration, and
native Linux amd64/arm64 Core Provenance on the FINAL exact head.
