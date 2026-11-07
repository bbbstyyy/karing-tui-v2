# ADR 0032: Separate declaration revisions from compiled runtime generations

- Status: Accepted
- Date: 2026-10-06

## Context

The daemon already journals immutable compiled generations and advances `daemon_state.config_revision` only after a core candidate has passed activation/verification.

That revision cannot also serve as user declaration state. A user may edit declarations that fail compilation, require missing resources, or are awaiting explicit apply. Conflating the two would either lose the user's requested state or falsely mark an unapplied declaration as active core configuration.

The plan requires the daemon to own declaration state and use optimistic revision checks for multiple clients.

## Decision

SQLite schema v4 adds an independent immutable declaration chain:

`declaration_revisions`

- monotonically increasing explicit revision;
- optional parent revision;
- exact declaration JSON bytes;
- SHA-256 of those bytes;
- bounded source identifier;
- UTC creation timestamp.

`declaration_state`

- singleton row;
- nullable current declaration revision.

Revision zero is the synthetic empty state and has no database row.

## Write contract

`CommitDeclaration(ctx, expectedRevision, document, source)`:

1. requires non-empty valid JSON;
2. enforces a 16 MiB maximum;
3. validates a bounded, log-safe source identifier;
4. begins a SQLite transaction;
5. reads the current declaration head;
6. rejects stale writers with `ErrDeclarationRevisionConflict`;
7. inserts immutable revision `expected + 1` with exact-byte SHA-256;
8. advances the singleton declaration head;
9. commits atomically.

No core apply or generation row is created by this operation.

## Read contract

`CurrentDeclaration` returns revision zero when no declaration exists.

`Declaration(revision)` reads immutable history and returns a defensive copy of the JSON bytes. Missing positive revisions fail with `ErrDeclarationNotFound`.

## Why this is separate from runtime generation state

The existing runtime revision remains the revision of **successfully committed core generations**.

The declaration revision is the revision of **user/configuration intent**, which may be newer than the applied runtime generation.

A future managed compiler coordinator will consume an exact declaration revision and produce a compiled artifact. The artifact/apply journal must record which declaration revision it came from before `managed_apply` can become true.

## Migration

Schema v4 is additive. Existing v1/v2/v3 databases gain empty declaration state and preserve all generations, apply journal entries, last-known-good state, recovery flags, and desired core state unchanged.
