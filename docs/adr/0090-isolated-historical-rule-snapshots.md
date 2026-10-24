# ADR 0090: Isolated bounded historical rule-resource snapshots (dry-run only)

- Status: **M4 prerequisite; no operator restore / activation is enabled.**
- Depends on: ADR 0084–0089.
- Environment: Linux user-space HTTP/SOCKS proxy; no TUN, no subscription/ISP routing layer.

## Motivation

An open file descriptor (ADR 0088) detects observed pathname swaps and protects an original inode from disappearing while a process holds it, but does not establish a separate reusable resource closure for future restoration and fallback. Historical core-check needs to prove that the target, current applied and LKG rule resources can be copied into independent private storage without trusting a pathname after verification.

## Implementation

`coreartifact.StagePinnedRuleSetSnapshot` creates a random private scope below `core/historical-check-snapshots` and copies the **deduplicated union** of existing pinned source/binary rule sets from their already-open no-follow descriptors. A copy is **never a hard link** to the shared content-addressed file. It must pass all of these checks:

1. Private, current-user-owned directories; clean absolute paths; bounded maximum of 128 descriptors and cumulative 128 MiB, at most 64 MiB per artifact.
2. Verify the original pin and content hash before copying, stream from the **open descriptor** under the bounded context, compare the copied byte count and SHA-256, then verify the original pin again.
3. Create the destination exclusively with owner-only permissions; mark it owner-read-only (`0400`); fsync each file and the scoped directory. Reopen and verify copied SHA-256, expected inode, size, mode, and exact allowed directory entries.
4. Verify both the pinned originals and the independent copies before and after the internal `core.Check`. Any difference rejects the dry-run result. A failure in isolated-copy creation does not reach core Check, activate, verify, commit, or modify the existing applied generation.
5. On success, error or canceled Check, close the scope and delete **only** the files and directory originally created by it, after checking inode identity and rejecting unexpected extra entries or replaced files. Cleanup failures are hard errors, not restore authorization.

This snapshot is **ephemeral** and scoped to the read-only compatibility operation. It does not rewrite or rebind the stored native configuration's `runtime_path` fields: the core's existing Check still uses the original historical paths; isolated copies are independently verified preparation evidence, not runtime inputs. No snapshot location is exposed to HTTP, CLI or TUI, and `restore_supported=false` and `restore_ready=false` remain invariants.

## Gaps before activation

A private `0400` file can still be chmod'd or replaced by the same Unix account, and pathname ABA is not impossible. Cross-process exclusion and an activation-time immutable resource namespace are not yet established. Abrupt process termination can leave an orphaned private check directory; future crash-safe recovery needs bounded, ownership-validated scavenging that cannot touch another active instance. Snapshot disk-use limits apply per check; persistent disk quota accounting and reservation across crashes remain a separate work item. A complete restore must also rebind native configuration paths to isolated resources with matching manifest provenance and core validation, durably pin both target and fallback across restart, prove live routing/DNS/selection readback, and fault-inject rollback-of-rollback.

The operation still does not activate a historical generation, expose a restore command, change five-layer routing order, CN preset, DNS semantics or the no-TUN/subscription-ISP-exclusion requirements.
