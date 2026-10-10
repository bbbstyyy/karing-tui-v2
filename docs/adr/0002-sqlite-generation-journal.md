# ADR 0002: Persist immutable generations and apply state in SQLite

- Status: Accepted
- Date: 2026-10-04

## Context

The project plan requires a single authoritative daemon writer, optimistic revision checks, immutable applied generations, last-known-good recovery, and explicit behavior when the process dies between writing configuration and proving that the proxy core is healthy.

A database transaction cannot make the external core process atomic with SQLite. Treating a successful database commit or a Clash API status code as proof that a new runtime configuration is active would violate the recovery model.

## Decision

The daemon uses a private SQLite database under `XDG_STATE_HOME/karing-tui-v2/state.db`. The first schema contains:

- immutable generation rows with the proposed base/target revision, compiled JSON bytes and SHA-256;
- singleton daemon state with the confirmed revision, applied generation, last-known-good generation and recovery-required bit;
- an append-oriented apply journal with one active slot and explicit phases: `prepared`, `activating`, `verifying`, `rolling_back`, plus terminal outcomes;
- schema migration metadata.

The SQLite driver is `modernc.org/sqlite`, selected to avoid CGO in Linux amd64/arm64 builds. The exact driver and matching `modernc.org/libc` versions are pinned in the module/dependency lock files.

SQLite runs with foreign keys enabled, WAL mode, `synchronous=FULL`, a finite busy timeout, bounded WAL checkpoint settings and `trusted_schema=OFF`. If WAL cannot be enabled, startup fails explicitly instead of silently changing durability behavior.

## Apply invariant

Preparing an apply does **not** advance the confirmed configuration revision. A candidate generation becomes applied only after the future core supervisor has moved the journal through activation and verification and then calls the commit operation.

Therefore:

1. `expected_revision` is compared with the last confirmed revision.
2. only one apply journal row may be active at once;
3. failed or rolled-back candidates remain auditable but do not replace the applied generation;
4. successful commit advances the revision and applied pointer atomically in SQLite;
5. last-known-good promotion is explicit and happens only after successful verification.

No network I/O or core process operation occurs inside a SQLite write transaction.

## Crash recovery

On daemon startup, unfinished journal rows are marked `interrupted`.

- A crash while still `prepared` does not imply that the core changed, so no core reconciliation flag is required.
- A crash in `activating`, `verifying`, or `rolling_back` sets `recovery_required`.
- While recovery is required, new apply preparation is rejected.
- A future core supervisor must re-establish the confirmed applied generation (or enter a hard Failed state) before clearing recovery.

This deliberately does not infer process ownership or configuration identity from a listening port alone.

## Security and limits

The state database is created as mode `0600`, symlink/non-regular paths are rejected, and ownership is checked against the current UID. The parent XDG state directory remains mode `0700`.

Compiled generation JSON is currently capped at 64 MiB. Generation retention/garbage collection remains separate M1 work and must be bounded before the project claims the long-term disk budget from the plan.

## Consequences

- The daemon now has a durable revision/generation substrate without depending on a particular sing-box build.
- Core activation can be implemented as external actions between journal phase transitions.
- Recovery state is visible even before core supervision exists.
- SQLite migration, backup and retention policy remain explicit engineering surfaces rather than hidden file replacement behavior.


## Schema v2: persist lifecycle intent separately from configuration revision

The singleton daemon state now stores `core_desired_state` with only two valid values: `stopped` and `running`. The default is `stopped`.

This is operational intent, not configuration content. Updating it therefore does not increment `config_revision`, create a generation, or touch the apply journal. An explicit stop can survive a daemon restart without being confused with a failed start or an interrupted apply.

The persistence primitive is implemented before lifecycle API wiring. Until the real core artifact and lifecycle endpoints are integrated, the daemon exposes the persisted value through status but does not automatically launch a core merely because the value is `running`.
