# ADR 0185 — Bind freshly created candidate scope to original inode

Status: Draft pending exact-head CI; T15/T23 scoped safety improvement.

## Context

After `MkdirTemp`, Stage had two paths calling `os.Remove(directory)`
without comparing the pathname's current inode with the originally
created scope. The parent advisory flock serializes cooperating
Karing-TUI instances, but not a same-UID process that renames a path.
If that path was replaced by an empty directory or symlink between
creation and an admission failure, blind path removal could delete a
different directory. Likewise, reopening an already replaced, private
0700 directory could satisfy the child lock/identity checks without
proving it was the inode just created by this Stage call.

This is a deterministic attack-window bug identified by source review,
not the established root cause of Issue #59's intermittent refusal.

## Decision

Capture `Lstat` metadata immediately after creating the new private
scope; fail closed if the scope cannot be verified. On a subsequent
pre-adoption refusal, remove the empty directory only if the path still
names that private, same-file inode. After opening the child fd and
flock, compare the candidate's locked directory identity against the
originally created inode and the current pathname before accepting it.

If the observed inode differs, close only the acquired fd and refuse
the operation: never discard/delete the foreign scope. Normal
pre-adoption cancellation still removes an unchanged, owned empty
scope. Cleanup remains nonrecursive and the source ciphertext untouched.

## Threat-model limit

`Lstat` followed by `os.Remove` is **not an atomic inode-conditional
unlink**. An adversary controlling a same-UID parent may still race
between the final identity check and removal. A future fd-relative,
kernel-enforced ownership operation is required to close that smaller
TOCTOU window. This change closes deterministic pre-existing
replacement windows and refuses to treat the replacement as a newly
created authorized candidate. Do not claim full protection against an
actively racing same-UID adversary.

## Verification and gates

Linux-only regression swaps the pathname at `scope_created`,
`scope_child_open` and `scope_child_lock_held`, including a symlink,
and verifies denial, preservation of the replacement and source
ciphertext; helper tests exercise identity-guarded cleanup in isolation.
The public restoration API, key checks, no-TUN policy, subscription/ISP
exclusions, no-auto-retry behavior and release flags are unchanged.

Require the exact head's CI, Go Race 4/4, Managed Core and native
amd64/arm64 Core Provenance to pass. Keep Issue #59 open; this fix does
not prove the cause of the observed intermittent staging refusal, nor
complete T15/T23 or authorize a live restore.
