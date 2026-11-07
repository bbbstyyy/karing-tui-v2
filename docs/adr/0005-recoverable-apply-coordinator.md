# ADR 0005: Apply configuration as a recoverable external transaction

- Status: Accepted
- Date: 2026-10-04

## Context

SQLite cannot make a child proxy process, its listeners, generated files, and local health checks part of one ACID transaction. Treating a successful JSON write or a successful Clash `PUT /configs` response as equivalent to an applied configuration would violate the project plan and can strand the daemon with persistent state that disagrees with the running core.

The existing storage layer already separates immutable generations, confirmed revision, last-known-good, and an apply journal. The missing piece is one coordinator that owns the order of external core actions around those durable phase changes.

## Decision

`internal/daemon.ApplyCoordinator` executes one candidate through the following sequence:

1. durably prepare an immutable candidate generation and active journal attempt;
2. load the immutable previous applied generation, if any;
3. run a bounded core/config check without changing the running core;
4. durably enter `activating`;
5. activate the candidate with a deadline;
6. durably enter `verifying`;
7. run bounded local verification;
8. commit the candidate as applied and last-known-good only after verification succeeds.

No external core operation runs inside a SQLite write transaction.

## Failure behavior

A failure before activation aborts the prepared attempt and leaves the confirmed applied generation untouched.

Any failure after activation begins attempts to restore the immutable previous generation. This includes:

- candidate activation failure;
- failure to persist the verification phase;
- local verification failure;
- failure to persist the final applied revision after verification.

A successful rollback records `rolled_back` and leaves the confirmed revision/applied pointer unchanged.

If rollback itself fails, storage atomically records the attempt as failed and sets `recovery_required=1`. New applies are then rejected until explicit reconciliation clears recovery. This is intentionally fail-closed: the daemon does not guess which generation is really serving traffic.

If journal persistence fails while trying to record rollback intent or completion, the attempt remains nonterminal/active. That also blocks another apply, and startup recovery will classify an interrupted activation/verifying/rollback phase as requiring reconciliation.

## Cancellation and deadlines

Check, activation, verification, rollback, and state transitions have explicit deadlines. Once an apply attempt exists, cleanup uses a bounded context detached from caller cancellation. Closing a TUI or canceling an HTTP request therefore cannot by itself prevent a prepared candidate from being aborted or an activated candidate from being rolled back.

This does not mean an accepted apply runs forever after client disconnect: every cleanup action is still bounded.

## Current integration boundary

The coordinator is tested against the real SQLite store and a fault-injectable abstract core. Tests cover successful commit plus deterministic failures in candidate check, activation, verification, durable commit, rollback, and check timeout.

`managed_apply` remains false. The coordinator is not yet wired to a provenance-approved KaringX/sing-box artifact, deterministic generated config directory, concrete local health checks, or process-level crash/power-loss integration tests. Those remain M1 gates.
