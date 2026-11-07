# ADR 0088: Descriptor-pinned historical rule-resource checks

- Status: M4 partial prerequisite. Historical restore remains **internal and non-activating**.
- Dependencies: ADR 0084–0087.
- Environment: Linux user space, no TUN; five-layer routing and CN preset remain unchanged.

## Problem

The internal historical compatibility check (ADR 0087) verified rule file paths before invoking core `Check`, then only rehashed the historical **target** files afterward. This left two avoidable gaps: a different, byte-identical inode could be substituted at the same pathname; and the live applied/LKG fallback metadata or rule resource could change during the check without being revalidated. Neither condition should be treated as evidence of a stable recoverable snapshot.

## Design

Add `coreartifact.PinRuleSet` to open the expected source/binary rule set with the established no-final-symlink and private-owner restrictions. Retain the descriptor for the duration of the check. Both initial and final validation require a regular current-user-owned private file, size cap, SHA-256 match, and that the content-addressed path still resolves to the **same inode** as the held descriptor. Repeated verification hashes the pinned descriptor, not merely whatever bytes happen to occupy the path. Close the descriptor on all paths, including errors.

The daemon now computes a **bounded union** of the historical target, current applied and last-known-good rule-resource manifests. Identical content-addressed paths share one pin. Reject unknown formats, off-root paths, too many distinct resources or a cumulative amount beyond the existing recovery-audit limit. Also snapshot all three SQLite generation artifact payloads and their stored hashes; compare/re-hash them before and after core `Check`. The operation remains serialized against daemon core transitions under the existing `OperationGate`, with the prepared journal entry aborted on exit.

Regression coverage includes the decisive counterexample: replace **only the fallback** rule file with the **same bytes** but a different inode during the core check. Rehashing the pathname would have passed; the held descriptor rejects the substitution. Tests also cover in-place mutation, unlink, symlink, permission drift, cancellation and an in-check fallback SQLite manifest hash alteration.

## Limits and future work

This is an **in-process bounded identity pin**, not a kernel-enforced immutable pathname or a durable resource lease. POSIX file descriptors cannot prevent a separate writer from temporarily swapping a pathname and restoring it before the next observation (ABA). Nor can they make SQLite, live control-plane state and core process activation one atomic operation. The actual restore still requires an isolated immutable **run-time** rule set path/lease covering both the restored candidate and its rollback chain, policy/control readback, explicit operator authorization, journaled activation and fault-injected rollback-of-rollback. Do not use this pin as an activation token.

No manual restore API/CLI/TUI was added. `restore_supported=false` and all `restore_ready=false` remain invariant; previously applied config and running core are not replaced by the compatibility check.
