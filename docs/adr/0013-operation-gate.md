# ADR 0013: Serialize daemon mutations through one operation gate

- Status: Accepted
- Date: 2026-10-05

## Context

The storage apply journal guarantees one active apply attempt, and ManagedCore serializes its own process transitions. Neither is sufficient to protect the daemon as a whole.

A lifecycle request can otherwise persist `stopped` while an apply operation has already read `running`, or a recovery action can race a user start. Holding a SQLite write transaction across external process work is not acceptable, so serialization must sit above the storage and core adapters.

## Decision

All future daemon mutations that can affect persistent configuration or core lifecycle must enter one `OperationGate`.

The gate:

- admits exactly one named mutating operation at a time;
- allows queued callers to cancel via their context before they enter;
- records the active operation name and UTC start time for status/diagnostics;
- always releases after success or failure;
- does not cancel the currently running operation merely because another caller times out.

Initial operation names will include lifecycle start/stop/reset, apply, rollback/recovery, and state-maintenance operations that can conflict with them.

Read-only status and diagnostic endpoints do not acquire the gate.

## Lock ordering

The operation gate is the outer daemon mutation lock. After entering it, an operation may use storage transactions and ManagedCore's internal process-transition mutex.

Code must not acquire the operation gate while already holding a ManagedCore transition lock or SQLite write transaction. This one-way ordering avoids deadlocks and prevents long external process work from holding database write locks.

## API consequence

Public lifecycle/apply endpoints are not enabled merely by adding this gate. Their handlers must explicitly execute mutation callbacks through it and map queued cancellation, recovery-required state, circuit-open state, and revision conflicts into versioned API errors.

The capability `operation_serialization=true` therefore describes an implemented safety primitive, while `core_lifecycle_api` and `managed_apply` remain false until those endpoint contracts are wired and tested.
