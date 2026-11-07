# ADR 0183 — Non-sensitive syscall failure classification for inert candidate staging

Status: Draft; CI evidence pending. Follows ADR 0182 and Issue #59.

## Evidence

The previous Race shard failure was localized to `stage=create_scope`
while independent archive authentication, SQLite verification and storage
reserve checks passed. ADR 0182 narrowed the next evidence boundary to
the new scope's mkdir/open/flock/inode checks. Its exact head passed the
full required CI and was merged, but the underlying intermittent refusal
was not causally explained.

A probe that records only the last checkpoint can identify the failing
operation, but not whether a syscall failed from descriptor exhaustion,
storage quota, a lock conflict, permissions, interruption or I/O error.
Emitting full errors in CI diagnostics would reveal private paths; retries
would conceal real safety refusals.

## Decision

Preserve the exported `StageInertRestoreCandidate` signature and public
`ErrUnsafeInertRestoreCandidate` and busy sentinels. In the existing
private nil-by-default test probe only, report fixed operation and errno
classes after an actual `MkdirTemp`, child `open(O_NOFOLLOW)` or
`flock(LOCK_NB)` failure. A rejected child identity uses a fixed
`scope_child_identity_refused` label. Error classes are a fixed
allowlist: storage capacity, descriptor pressure, lock contention,
interruption, permissions, missing path, symlink, I/O, or other.

Never emit an error string, OS path, key, hostname, archive digest,
ciphertext or plaintext. The callback cannot reverse a refusal, change
the error seen by a production caller, retry, widen permissions or
authorize recovery. Deterministic table tests verify common errno
classes and that wrapped/private error strings are not exposed.

## Limits and acceptance

No fix for the root cause is asserted. A successful same-head CI run
does not close Issue #59 or promote T15/T23 recovery readiness.
Merge only after normal CI, four Race shards, Managed Core and both
native Linux architecture checks pass on the exact submitted head.

No TUN, subscription/ISP routing source, Core lock change, network
access, public diagnostics or modification to stable `main`.
