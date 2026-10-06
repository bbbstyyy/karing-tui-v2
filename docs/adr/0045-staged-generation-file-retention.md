# ADR 0045: Bound staged generation files independently from durable generation history

- Status: Accepted
- Date: 2026-10-06

## Context

The daemon persists authoritative generation config, manifest, source-map, apply journal, applied pointer, and last-known-good pointer in SQLite. Managed core execution also materializes immutable copies under the private state root:

```text
core/generations/<generation-id>/config.json
```

Those filesystem copies are execution artifacts, not the authoritative history. Without retention they grow once per checked/applied generation, including failed candidates, which conflicts with the plan requirement that long-running disk use be bounded.

Deleting arbitrary generation directories is unsafe because the currently applied generation, the last-known-good generation, or the candidate being checked/activated may still be required for restart or rollback.

## Decision

`coreartifact.Store.PruneStagedGenerations` implements fail-closed filesystem retention for staged generation directories.

The managed core keeps:

1. the generation currently being checked, started, activated, or restored;
2. the durable `applied_generation_id`;
3. the durable `last_known_good_generation_id`;
4. the newest eight staged generation directories.

All older staged directories may be removed because the authoritative config bytes remain in SQLite and can be re-staged through the existing hash-verified path.

Cleanup runs before staging a candidate in managed-core check/start/activate/rollback paths. Therefore a cleanup failure happens before a core restart or generation switch.

## Safety properties

The pruning path:

- accepts only positive numeric generation directory names;
- rejects symlink, permissive, foreign-owner, non-directory, or unexpected top-level entries;
- permits only `config.json` and crash-left `.config-*.tmp` regular private files inside a prunable generation directory;
- validates all prune candidates before deleting the first one;
- honors context cancellation;
- fsyncs directories after deletion;
- never treats cleanup failure as permission to silently continue with a different runtime generation.

The keep set is additive: applied/LKG/candidate generations are protected even when they are older than the ordinary newest-eight retention window.

## Scope boundary

This ADR bounds duplicated **filesystem execution artifacts only**. It does not delete SQLite generation rows, declaration revisions, or apply-journal history. Durable database/history compaction requires a separate design because those rows carry audit and recovery relationships and must not be removed merely to reduce disk usage.

The daemon capability `staged_generation_gc=true` means this bounded filesystem cleanup is available. It does not claim full database-history retention is complete.
