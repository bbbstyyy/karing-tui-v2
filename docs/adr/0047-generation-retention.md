# ADR 0047: Bound generation payload retention while preserving compact apply audit

- Status: Accepted
- Date: 2026-10-07

## Context

The immutable generation table stores the full compiled config, manifest, and
source map needed for deterministic rollback and diagnosis. Those payloads are
individually bounded, but retaining every failed candidate and every historical
confirmed generation would still make long-running disk use grow with update
count.

The project plan requires at least the current and previous effective
generations to remain recoverable, recommends keeping the latest five confirmed
generations, requires pending/rollback references to be protected, and requires
new transactions to fail closed under storage pressure instead of deleting the
only recovery point.

Deleting the apply journal to save space would violate the audit requirement.
Keeping full generation payloads forever is not a viable audit strategy either.

## Decision

SQLite schema version 5 adds `apply_history`, a compact terminal-attempt audit
table. Before a new generation is prepared, and when explicitly requested by an
operator, the store runs one retention transaction:

1. terminal apply-journal rows are copied into `apply_history` with generation
   IDs, revisions, final phase/error, config/manifest/source-map hashes, and
   timestamps;
2. those terminal rows are removed from the live journal, which remains the
   active transaction journal;
3. the protected generation set is calculated from the current applied
   generation, last-known-good generation, active candidate plus its previous
   generation, and the newest configured number of confirmed generations;
4. generation payload rows outside that protected set and outside any live
   journal reference are deleted.

`Store.Attempt` reads the live journal first and falls back to compact history,
so callers can still inspect the final outcome of an archived attempt after its
large payload has been reclaimed.

The default policy keeps five confirmed generations and caps logical retained
generation payloads at 640 MiB. The quota counts config + manifest + source-map
payload bytes. A new apply runs retention first and is rejected with
`ErrGenerationStorageBudget` if protected payloads plus the candidate would
exceed the configured budget. Rejection happens before a new generation or
journal intent is written and therefore cannot disturb the healthy core.

Deployment may override the policy with:

- `KARING_TUI_KEEP_CONFIRMED_GENERATIONS` (minimum 2, maximum 1000);
- `KARING_TUI_GENERATION_QUOTA_MIB` (positive MiB value).

The daemon exposes the effective policy and usage through
`GET /v1/storage/retention`; `POST /v1/storage/prune` performs the same safe
retention transaction explicitly. The CLI exposes these as
`storage retention` and `storage prune`.

## SQLite file-size boundary

The quota is a logical payload quota, not a promise that the SQLite file's
high-water size immediately shrinks. Deleted pages are reusable by later
transactions, preventing linear payload growth under repeated similarly sized
updates.

The hot path intentionally does not run `VACUUM`. Vacuum requires a database
rewrite and additional free space and can stall the management plane. Offline
or maintenance compaction can be added separately together with backup and
free-space checks.

## Failure behavior

Retention never deletes a current, last-known-good, active-candidate, or
active-rollback generation reference. Foreign keys remain enabled as an
additional fail-closed guard.

If retention fails, the new apply is rejected before external core changes.
Existing proxy service continues using the confirmed generation.

If protected payloads alone exceed the configured quota, status reports
`over_budget=true`; existing service remains intact and further applies are
rejected until an operator raises the quota or a future supported workflow
changes retained state. Storage pressure never causes a protected recovery
generation to be deleted.

## Validation

Storage tests cover compact audit fallback after payload pruning, retaining the
configured confirmed-generation window, protecting active candidate/previous
references, reclaiming a failed candidate after it becomes terminal, and
rejecting an over-budget candidate without changing revision or applied state.

Daemon tests cover retention policy parsing plus the status/prune API.
