# ADR 0095 — Flock-guarded crash recovery for private SQLite snapshots

- **Status:** M4 internal-only backup safety prerequisite; neither backup export nor restore is available.
- **Supersedes:** the "no orphan recovery" gap documented in ADR 0094.
- **Environment:** ordinary Linux user, local filesystem, no TUN, unchanged CN preset/five-layer routing and no subscription/ISP routing layer.

## Problem

ADR 0094 makes a self-contained WAL-consistent private SQLite copy by using VACUUM INTO. A daemon crash or SIGKILL can leave a complete or partially written state.db containing credentials. A naive recursive sweep would be unsafe: another process could still be performing a legitimate VACUUM, and a cleanup worker might see a newly created but not-yet-locked directory.

## Lifetime and synchronization

Each new .sqlite-snapshot-v2-<alphanumeric> directory holds an exclusive Linux flock on its O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC descriptor until the DatabaseSnapshot.Close operation finishes. Closing the descriptor or process death releases the lock. A short, context-bounded parent directory flock serializes both (1) MkdirTemp through locking the new child, and (2) discovery and reclamation. The parent lock is released **before** any SQLite copying or integrity validation, so active copies do not serialize behind long VACUUMs.

Close takes the parent lock before deleting its own scope. It accepts only the precise original directory inode and private owner/mode, and the expected state.db single-link regular file at the originally created inode. It uses unlinkat relative to the held scope directory descriptor, never RemoveAll. It rejects unknown entries or changed identity and allows a retry after an operator fixes an unsafe scope. Successful removal fsyncs the parent before releasing the locks.

## Bounded, opt-in stale-scope recovery

ReclaimOrphanedDatabaseSnapshots is an internal-only operation. It is opportunistically called when a new database snapshot is requested using the same existing private parent. It is not invoked by the daemon at startup or from HTTP, CLI, TUI or a periodic scheduler.

It scans at most **32 immediate scopes**. Directory names must have the exact .sqlite-snapshot-v2- prefix followed by only ASCII letters/digits; each scope must be owned by the current UID and mode 0700. Busy/actively locked scopes are **counted and skipped**. Unlocked scopes may contain only zero files (crash after mkdir) or one owner-owned single-link regular state.db file of mode 0600 and size 0–768 MiB (crash before/during/after SQLite VACUUM). File contents need not be valid SQLite to reclaim partial copies. Symbolic links, nested directories, hardlinks, unexpected filenames, modes, ownership, file sizes and excess scope counts are hard errors. Content is never emitted or logged.

All reclamation happens under the locked parent and child scope; inode identity is checked again before unlinkat and directory deletion. No symlink target is followed, no recursive deletion is used, and the parent is fsynced. Interrupted deletion can be retried on the next invocation; an unknown scope requires manual inspection instead of silent cleanup.

## Evidence and remaining blockers

Tests cover a child process exiting without closing its flock, a separate process skipping a still-active scope, simultaneous new snapshot creation, bounded parent-lock contention, opportunistic old-scope cleanup and refusal of unsafe paths, foreign files, symlinks, hardlinks, public files, oversize files, nested entries and more than 32 scopes. Existing WAL, SHA-256, SQLite quick_check and immutable-snapshot tests remain.

This operation **does not** reserve total on-disk space, provide an at-rest encrypted archive, bind SQLite to a snapshot of external rules/core resources, handle a damaged or over-budget scope automatically, or protect against malicious processes under the *same UID*. Crash leftovers persist until the next internal copy or an explicitly requested internal recovery pass. Manual restoration remains disabled and the recovery audit still reports restore_supported=false and restore_ready=false. Future work: resource-closure inventory + manifests, secret-aware encrypted packaging, full transactionally guarded restore including rollback-of-rollback and operational T15/T23 evidence.

## Mixed-version safety

Earlier ADR 0094 code used the same parent with unleased .sqlite-snapshot-<random> directories. They are deliberately **not recognized by the v2 scavenger**, because an older concurrently running process may still be writing one. Encountering such an entry blocks a new snapshot until the operator verifies that the old process has exited and resolves the legacy scope manually. This is a fail-closed migration boundary, not automatic legacy garbage collection.
