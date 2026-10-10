# ADR 0034: Verify declaration integrity before schema compilation

- Status: Accepted
- Date: 2026-10-06

## Context

Declaration revisions are immutable SQLite records and strict runtime artifacts can now carry exact declaration provenance. The remaining trust boundary is the handoff from stored declaration bytes into the versioned schema compiler.

That handoff must not assume that the database hash is correct, mutate stored buffers, or let a compiler artifact choose its own declaration provenance.

## Decision

`DeclarationCompileCoordinator` owns the revision-to-compiler handoff.

For an explicitly requested positive revision it:

1. loads that exact revision from the declaration store;
2. verifies that the store returned the same revision number;
3. requires non-empty declaration bytes and a recorded SHA-256;
4. recomputes SHA-256 over the exact stored bytes and rejects any mismatch;
5. passes a defensive copy of those exact bytes to an injected declaration compiler engine;
6. binds the returned native artifact to the stored revision and SHA-256 using the compiler provenance API.

Revision zero is the synthetic empty state and cannot be compiled.

## Separation from apply

This coordinator does not call managed apply. Compilation failure must not create a generation or disturb the running core.

A later explicit apply coordinator/API may compose:

`declaration revision -> DeclarationCompileCoordinator -> NativeConfigArtifact -> ApplyNativeArtifact`

while still requiring a separate expected runtime config revision for the apply journal CAS.

## Schema independence

The coordinator depends on a small `CompileDeclaration(context, []byte)` interface rather than a concrete JSON schema implementation.

This lets the versioned declaration parser/compiler evolve without duplicating revision-integrity and provenance-binding logic.

The compiler receives a defensive byte copy, so even a buggy parser cannot mutate the store-owned declaration buffer.

## Failure behavior

Stored hash mismatch, incomplete revision records, revision-number mismatch, schema compiler failure, or artifact provenance-binding failure all stop before runtime apply.
