# ADR 0086: Atomically sealed historical restore preparation (storage only)

- Status: Accepted as a **non-exposed M4 transaction primitive**; no manual rollback endpoint exists.
- Scope: Linux unprivileged HTTP/SOCKS core; no TUN or subscription/ISP routing layers.

## Problem

A read-only historical audit (ADR 0084/0085) does not hold a lease on retained payloads, current selection, routing mode, desired core state, or the current declaration. Reusing a historical generation ID directly would bypass the existing immutable candidate/apply journal lifecycle, and performing ordinary `PrepareApplyWithMetadata` after a separate audit would leave a race between checking an old candidate and committing an apply.

## Storage transaction

`storage.PrepareHistoricalRestore` requires an explicit `HistoricalRestorePrecondition` and performs all database operations in one SQLite transaction. It verifies:

1. The caller's exact expected configuration revision, applied and last-known-good IDs, current declaration revision/hash, selection revision, routing mode, private-direct flag and desired core state, with no recovery-required flag or active apply.
2. A **retained** historical generation with bounded JSON and matching SHA-256 for native config, manifest and source map. It must have a `committed` record, either in the live journal or in archived `apply_history`; archived records must match the three generation payload hashes. Prepared, failed, rolled-back, interrupted or pruned generations are rejected.
3. Manifest config hash and referenced historical declaration revision/hash are still consistent with the original immutable declaration bytes.
4. Retention quota can hold a second copy of the generation **without first pruning any historical payload**.

On success it creates a **new** immutable generation and `prepared` journal entry with the currently applied generation as the previous rollback target. Schema v17 adds nullable `generations.restore_origin_generation_id` for provenance without a restrictive foreign key that would prevent retention of compact history. Original historical payloads remain untouched. The confirmed revision, applied generation and last-known-good pointers are **not** changed.

A crash before activation is handled by the existing prepared-attempt cleanup; recovery after activation must use the existing journal state machine. The method itself neither checks nor contacts the core, performs no network/file IO, and is not reachable from the CLI, TUI or HTTP API.

## Explicitly *not* solved

The daemon does not yet expose manual restore because it must pin and recheck the exact rule-resource closure and selector binding **at activation time**, verify compatibility with the currently approved core binary/control plane, coordinate the operation gate, and use `Check → Activate → Verify → Commit` with fault-injected rollback-of-rollback. A stored hash is not a core compatibility result. No endpoint may activate a historical generation merely because this preparation returned `PhasePrepared`.

ADR 0084/0085 status semantics remain: `restore_supported=false` and all `restore_ready=false`, including when this internal primitive exists. The operation does not change CN presets, five-layer source ordering, DNS or subscription/ISP route exclusion.
