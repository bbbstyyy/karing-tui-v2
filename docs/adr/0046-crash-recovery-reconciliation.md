# ADR 0046: Reconcile interrupted applies before clearing recovery state

- Status: Accepted
- Date: 2026-10-07

## Context

The apply journal already records prepared, activating, verifying, and
rolling_back before the corresponding external core transitions. On daemon
startup, active attempts are converted to interrupted; interruptions after
activation begins set recovery_required=1.

That durable marker is necessary but was not sufficient. The previous startup
path then refused lifecycle restore while recovery was required, and there was
no runtime reconciliation step that could prove the data plane had returned to
the confirmed applied generation. A crash during activation or verification
could therefore leave the daemon permanently fail-closed without a path to
repair itself.

There is also a Linux process-ownership boundary. A standalone daemon process
must not leave its managed sing-box child running if the daemon itself is
abruptly killed outside a service manager.

## Decision

The managed Linux core now sets PR_SET_PDEATHSIG through Go's
SysProcAttr.Pdeathsig to SIGKILL for the direct core process. Normal stop
still uses the supervisor's graceful TERM/timeout/KILL sequence. The
parent-death signal is reserved for the abnormal case where no supervisor
remains to perform escalation.

Startup recovery is split into two durable steps:

1. storage.RecoverInterrupted classifies and closes the interrupted journal
   attempt without changing the confirmed applied generation.
2. RecoveryCoordinator asks ManagedCore to reconcile the runtime against the
   persisted state. Only after that succeeds does it clear recovery_required.

For persisted stopped intent, reconciliation enforces a stopped supervisor.
For persisted running intent, reconciliation stages and verifies the confirmed
applied_generation_id, restarts that exact generation, and runs the local
readiness probe. Missing or invalid generation artifacts fail closed and leave
the recovery flag set.

serverRuntime.Restore performs reconciliation under the existing operation gate
before ordinary lifecycle restore. A failed reconciliation is retained as the
restore error exposed by status; the management API remains available for
diagnosis, and a later daemon restart can retry the idempotent reconciliation.

## Crash-window invariant

- Crash while only prepared: the candidate never had permission to change the
  data plane, so startup marks the attempt interrupted without requiring core
  reconciliation.
- Crash in activating, verifying, or rolling_back: startup restores the last
  durably confirmed applied generation (or stopped intent) before clearing
  recovery.
- Crash after CommitApplied commits: SQLite atomically exposes the new applied
  generation, so normal lifecycle restore uses that new generation.

The recovery flag is never cleared merely because a daemon restarted.

## Validation

Linux storage tests now launch a separate test process, durably enter each
journal phase, kill that process with SIGKILL without closing SQLite, reopen
the WAL database, and assert the confirmed generation/revision plus recovery
classification.

The exec-runner test also creates a real managed child through an intermediate
parent process, kills the parent, and verifies the child no longer remains
running. Managed-core unit tests cover both persisted running and stopped
recovery intents and refuse a running reconcile without an applied generation.

A combined recovery fixture now verifies that a running reconcile restores one
coherent confirmed state: the exact applied generation/config hash is staged
and bound, the content-addressed rule-set resource from that generation's
manifest is re-verified, CurrentSelected is resolved through that generation's
declaration provenance, and the persisted routing mode/privateDirect policy is
restored before readiness succeeds. This complements the real SIGKILL journal
fixtures: phase classification is exercised by abrupt process death, while the
managed-core fixture proves the post-crash reconciliation does not mix config,
rule resources, selection provenance, or routing policy from different states.
