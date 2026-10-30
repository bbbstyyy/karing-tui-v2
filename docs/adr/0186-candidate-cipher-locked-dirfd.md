# ADR 0186 — Ciphertext staging anchored to the leased directory descriptor

Status: Draft implementation; exact-head CI pending (M5, T15/T23 partial).

## Problem

ADR 0185 binds a freshly created candidate scope to the directory inode
seen immediately after MkdirTemp and validates the opened child lease.
However, copying ciphertext subsequently used a full path to create
`candidate.ktbackup`. `O_NOFOLLOW` on a full pathname only rejects a
symlink at its final component. A same-UID actor ignoring the parent advisory
flock could rename or replace the intermediate candidate directory after
its lock was acquired but before the target file was created. This could
write encrypted candidate data into an unrelated private directory or a
symlink target.

This is a distinct source-reviewed path-race hazard, not an established
explanation for Issue #59's occasional create_scope staging refusal.

## Decision

- At ciphertext copy start, verify the candidate has a locked, private
  original directory identity. Create the destination with Linux
  `openat(locked_dir_fd, "candidate.ktbackup", O_WRONLY|O_CREAT|O_EXCL|
  O_NOFOLLOW|O_CLOEXEC, 0600)` instead of an absolute `open` call.
  Because the fd refers to the leased inode, path substitution cannot
  redirect the write to a different directory inode.
- Preserve the existing full SHA-256 of the source ciphertext, exact
  archive length, source path/fd identity, target 0600 regular-file
  identity, fsync and complete independent encrypted preflight.
- Revalidate directory pathname/fd identity after copying and after
  the final authenticated preflight; reject any lost lease. Never
  infer restoration authority from an isolated ciphertext.
- Provide only fixed test-only phase labels before/after opening the
  fd-relative target; keep public APIs, error sentinels, no-auto-retry
  behavior and nonrecursive owned-scope cleanup unchanged.

## Tests and limitations

Linux fault-injection tests replace the candidate pathname with a
different 0700 directory or symlink to a foreign 0700 directory at
three copy-phase boundaries, asserting fail-closed behavior and no
ciphertext in the substitute. Verify that cancellation before openat
leaves no newly retained scope. No real restore or live state mutation.

An uncooperative same-UID actor can still rename the original locked
inode and leave its encrypted partial contents orphaned; Stage cannot
safely delete an inode whose pathname no longer matches. This is safer
than deleting an unrelated directory. It does **not** establish the
root cause of Issue #59, nor fully eliminate all same-UID filesystem
races elsewhere. The issue remains open.

Do not claim T15/T23 completion, T20/T25 soak, or production release.
No TUN, subscription/ISP routing source, Core update or stable main
modification. Require exact-head ordinary CI, Race 4/4, Managed Core
Integration and native Linux amd64/arm64 Core Provenance to pass before
merge.
