# ADR 0010: Materialize runtime generations as immutable private files

- Status: Accepted
- Date: 2026-10-05

## Context

SQLite owns the durable generation identity and config bytes, but the standalone core consumes a file path for `check -c` and `run -c`. Writing candidates to a mutable shared path would break the generation/apply journal model: a file could change after it was checked, after activation started, or while a rollback refers to it.

The runtime file layer therefore needs the same immutability boundary as the database generation row.

## Decision

`internal/coreartifact.Store` materializes a generation at:

`<state>/generations/<generation_id>/config.json`

The store requires:

- a positive generation ID;
- an expected SHA-256 supplied by the durable generation record;
- an absolute private state root owned by the current UID;
- 0700 state/generation directories;
- a 0600 regular config file;
- no symlink generation directory or config target.

A new file is written to a private temporary file, fsynced, and then published with a hard-link create operation so an existing `config.json` is never overwritten. The generation directory is fsynced after publication.

If the destination already exists, staging succeeds only when its content hashes to the exact expected generation SHA-256. Different content for the same generation ID fails with `ErrGenerationImmutable`.

## Consequences

- Core `check`, activation, and rollback can all refer to one immutable path for a generation.
- A caller cancellation before publication does not promote a candidate file.
- Replaying a valid generation after daemon restart is idempotent.
- Tampered or permissive generation paths fail closed instead of being silently repaired.
- Garbage collection remains a later M1 task and must never delete the applied, last-known-good, active-attempt, or recovery-required generation.
