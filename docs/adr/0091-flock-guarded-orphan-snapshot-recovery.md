# ADR 0091 — Bounded cross-process orphan recovery for historical check snapshots

- Status: **M4 internal safety prerequisite; manual restore and activation remain disabled.**
- Supersedes part of ADR 0090's orphan-cleanup gap. Does not establish an activation-time resource lease or make the core consume isolated snapshot paths.
- Scope: Linux user-space HTTP/SOCKS operation, no TUN, no subscription/ISP routing layer.

## Problem

ADR 0090 materializes private temporary copies of the historical target and applied/LKG fallback rule-set closure for a **non-activating** core compatibility check. Clean termination removes only recognized copies, but SIGKILL, crash, or loss of power may leave up to 128 files / 128 MiB per temporary scope on disk. Deleting every `.check-*` directory on the next run would be unsafe if another daemon process is still checking it. A further race exists between the creation of a fresh directory and acquiring its lock: without coordination, a simultaneous scavenger could delete that new but not-yet-locked scope.

## Linux directory locks and bounded recovery

Each `RuleSetSnapshot` holds a Linux exclusive `flock` on an `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` directory file descriptor for its **entire** staging/check/cleanup lifetime. The lock is automatically released on process death. The private parent `historical-check-snapshots` directory uses a short, context-bounded exclusive `flock` during (a) creation of a new directory through acquisition of its own lock, and (b) scans/reclamation. The two operations therefore cannot observe an unlocked half-created scope. The parent's lock is released before `core.Check`, allowing other active scopes to coexist.

`coreartifact.ReclaimOrphanedRuleSetSnapshots` is a bounded, internal-only garbage collector. It runs opportunistically before staging the next internal compatibility-check snapshot; it is **not a reason to stop or restart an otherwise healthy running proxy**. A missing parent directory is a no-op. The caller must supply a clean absolute core state root; root and parent must be real current-user-owned private directories, opened/checked without following final symlinks. Scan at most 32 scope directories per invocation. Each scope must follow the exact `.check-<alphanumeric>` format, be privately owned, and accept a non-blocking exclusive directory lock. Busy/active scopes are counted and skipped, not touched.

A stale scope is eligible only if it contains no more than 128 directly contained files with lower-case SHA-256 plus `.json` or `.srs` names; no subdirectories/symlinks/other entries. Each file must be a single-link ordinary current-user-owned file with mode **0400** (completed) or **0600** (interrupted copy), max 64 MiB/file, and max 128 MiB/scoped total. File contents need not hash to the name for deleting an interrupted partial copy, but name/type/owner/size/mode and inode identity MUST be checked before unlinking. All deletes are nonrecursive, relative to the locked directory descriptor (`unlinkat`), with inode revalidation; the directory itself is removed only after all expected contents are gone, then its parent is fsynced. A lock or inspection error is a hard refusal, not a fallback to `RemoveAll`. A later pass may finish a partial deletion.

## Tests and remaining risks

Tests cover independent locked descriptors, skip of live scopes and later reclamation after simulated process death, partial 0600 file recovery, unknown entry, symlinked scope/parent, world-readable file, replaced file, canceled request, scope-count budget and automatic scavenging by the next check without disrupting another active scope.

The design still trusts the current UID, as stated in the project threat model; it is not an anti-malware defense against hostile same-UID processes. A sudden crash during cleanup can require retry, and a malicious/unknown directory fails closed rather than being erased. The 32-scope cap deliberately requires bounded operator intervention for pathological accumulation; it is not a durable disk space reservation. This recovery only runs when a new historical compatibility check stages a nonempty rule-set closure; startup-wide cleanup and periodic pressure-triggered maintenance are future decisions. It does not protect core activation, rebind native config paths, or provide a cross-restart rollback-of-rollback lease.

Manual historical restore remains unavailable (`restore_supported=false`, all `restore_ready=false`). The existing automatic apply rollback and all CN/five-layer/DNS/no-TUN constraints remain unchanged.
