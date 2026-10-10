# ADR 0089: Reclaim failed historical dry-run payloads without history pruning

- Status: Accepted as an **internal M4 recovery-check safeguard**. Manual restore remains disabled.
- Depends on ADR 0084–0088.
- Scope: Linux user-space proxy, no TUN, no subscription/ISP routing layer.

## Problem

ADR 0086 deliberately creates a *new* immutable SQLite generation for each historical compatibility check, and ADR 0087 always aborts it instead of activating it. However, `AbortPrepared` leaves the candidate's large native config, manifest and source map in `generations` until the general retention job runs. `PrepareHistoricalRestore` must fail closed on quota exhaustion rather than prune retained history to make room. Repeated checks could therefore consume the reserved quota and block subsequent legitimate checks or configuration applications. This contradicts the long-running stability and disk-pressure requirements of `docs/plan.md` §13.5.

## Targeted SQLite cleanup

The internal historical core-check now calls `storage.ReclaimAbortedHistoricalCheck` *after* a successful `AbortPrepared`, using another cancellation-independent, bounded storage transaction. The cleanup is not a broad `PruneRetention`. It must prove all of the following **inside the transaction**:

1. The journal attempt still exists and points to a generation created by the historical restore preparation path (`restore_origin_generation_id` is present and valid).
2. The journal is exactly `phase=failed`, `active_slot IS NULL`, and has the dedicated `HistoricalCheckAbortReason` marker that is only written by `AbortPrepared` directly from `PhasePrepared`. A rollback failure, crash-recovered `interrupted` attempt, activating candidate or normal unmarked failed apply is never eligible.
3. The candidate generation is not applied, last-known-good, or referenced as either candidate or previous generation by **any other** live or archived journal attempt. `recovery_required` must be false.
4. Insert the original failure journal's metadata and hashes into `apply_history` without ignoring uniqueness collisions, delete this one terminal live-journal entry, then delete exactly this one unconfirmed generation. All changes commit atomically or none do. The original historical source, applied/LKG generations and their resources remain untouched.

Even when core Check reports failure, the protected journal slot is aborted and the target candidate is reclaimed. Cleanup errors are treated as hard check failures; they never authorize restore, activation, or a fallback to direct mode. An unexpected process termination before cleanup can leave an orphan that the existing crash-recovery and bounded retention path must handle. Staged core config files remain covered by the existing staged-generation pruning policy, separate from SQLite quota.

## Tests and limitations

Regression tests cover an archived terminal failure with intact original and LKG, repeated checks at a quota that fits only one candidate, rejection of active/ordinary/incorrectly-marked/rollback-style/referenced/recovery-required candidates, archive conflict rollback, and interrupted attempts. The daemon-level test repeats the actual guarded core check and verifies its quota is returned on success **and** core-check failure.

**No manual historical activation, operator receipt, durable immutable runtime resource lease, or rollback-of-rollback is provided.** This is a resource-safety prerequisite for further work, not a declaration of M4 or T15/T23 acceptance. Public recovery audit semantics remain `restore_supported=false`, every `restore_ready=false`; CN presets, five-layer routing, DNS and the subscription/ISP exclusion remain unchanged.
