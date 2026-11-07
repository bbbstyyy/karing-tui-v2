# ADR 0036: Apply declarations as a two-revision transaction

- Status: Accepted
- Date: 2026-10-06

## Context

Declaration revisions and runtime config revisions represent different immutable histories.

A declaration revision identifies exact user intent bytes. A runtime config revision identifies the last generation that passed core check, activation, behavior verification, and durable commit. Reusing one revision number for both would make stale-write detection ambiguous and would weaken rollback semantics.

The daemon already has:

- immutable declaration revisions with SHA-256 integrity checks;
- a versioned schema compiler;
- declaration provenance binding on native artifacts;
- an apply journal with config-revision CAS, verification, rollback, and recovery state.

The missing step is a public operation that composes those pieces without creating a race between compilation and apply.

## Decision

`POST /v1/declaration/apply` accepts two independent revision values:

- `declaration_revision`: the exact positive immutable declaration revision to compile;
- `expected_config_revision`: the caller's expected current committed runtime config revision.

The daemon executes the complete operation under one `OperationGate` critical section:

`load declaration -> verify declaration SHA-256 -> compile schema -> bind provenance -> prepare apply -> core check -> activate -> verify -> commit`

The compile and apply stages are not exposed as two separately interleavable runtime operations.

The successful response reports declaration identity, native config identity, apply attempt/generation IDs, and base/target runtime config revisions.

## Historical declaration revisions

The apply API does not require `declaration_revision` to equal the current declaration head.

Declaration revisions are immutable, so explicitly applying an older revision is deterministic and useful for rollback, reproduction, and diagnosis. Runtime stale-write protection remains the responsibility of `expected_config_revision`.

## Failure behavior

- missing declaration revisions fail before generation creation;
- corrupt declaration provenance fails before apply;
- runtime config revision conflicts return a conflict and do not replace the committed generation;
- candidate check failures never activate the candidate;
- activation or verification failures use the existing rollback path;
- rollback failure leaves recovery-required state as defined by the apply journal.

The HTTP handler uses a detached bounded operation context so client disconnect cannot abandon cleanup after an apply transaction has begun.

## Capability boundary

`declaration_apply_api` is advertised only when both the declaration compiler and managed apply coordinator are available. The existing `managed_apply` capability becomes true at the same boundary.

Compile preview remains a distinct non-mutating operation.
