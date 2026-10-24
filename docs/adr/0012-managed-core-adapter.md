# ADR 0012: Compose core lifecycle and apply through one ManagedCore adapter

- Status: Accepted
- Date: 2026-10-05

## Context

M1 now has the required primitives separately: durable applied-generation state, immutable generation files, a locked core artifact verifier, a generation-bound runner, a bounded supervisor, authenticated local readiness probes, lifecycle intent persistence, and an apply transaction journal.

Those pieces must be composed through one owner. If lifecycle and apply code each create their own process runner, they can race, launch two cores, disagree about which generation is active, or bypass the restart circuit.

A second semantic issue is applying configuration while the user has explicitly stopped the proxy. Applying a candidate must still validate real local behavior, but it must not silently change the persisted stopped intent into a permanently running core.

## Decision

`internal/daemon.ManagedCore` is the single adapter shared by `LifecycleCoordinator` and `ApplyCoordinator`.

The production constructor composes:

- the durable storage source for applied generation bytes and SHA-256;
- `coreartifact.Store` for immutable generation materialization;
- `core.GenerationRunner` for exact generation path + hash binding;
- `coreartifact.Verify` before every core check/start;
- one `core.Supervisor` instance;
- one authenticated `coreapi.LocalHealthProbe`;
- fixed-capacity stdout/stderr ring buffers.

### Lifecycle start

A normal lifecycle start loads the confirmed applied generation from SQLite, refuses to start during `recovery_required`, stages and binds the immutable generation, asks the existing supervisor to start, and waits until the supervisor reaches `running` or a bounded failure state.

No applied generation produces an explicit `ErrNoAppliedGeneration`; the daemon does not invent a DIRECT-only configuration.

### Apply activation

Before activation, ManagedCore reads the persisted desired lifecycle state.

If desired state is `running`, candidate activation restarts into the candidate and leaves it running after verification.

If desired state is `stopped`, activation may temporarily start the candidate so the authenticated local control API and all three Mixed listeners can be verified. After verification it stops the core again. The persisted lifecycle intent is never changed by the apply adapter.

### Circuit breaker behavior

An explicit new configuration apply and a last-known-good rollback are operator-driven corrective actions. They are allowed to clear the supervisor circuit immediately before the generation switch. Ordinary lifecycle start does not implicitly clear the circuit.

A rollback to a previous generation preserves the original apply-time running/stopped intent. A stopped configuration is rebound without leaving a core process running.

## Concurrency boundary

ManagedCore serializes its process transitions internally. This is necessary but not sufficient for the public daemon API: lifecycle mutations and configuration apply requests must also be serialized at the daemon operation layer so a lifecycle request cannot change persisted intent halfway through an apply transaction.

For that reason `managed_core_adapter=true` does not enable `managed_apply`, `core_lifecycle_api`, or `core_supervision`. Those capability flags remain false until the server owns the supervisor loop and exposes serialized API operations with crash/recovery tests.
