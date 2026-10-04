# ADR 0003: Keep core restart ownership bounded and explicit

- Status: Accepted
- Date: 2026-10-04

## Context

The daemon must eventually own the KaringX/sing-box child process while `systemd --user` owns the daemon. The two layers must not compete to restart the same process, and an invalid deterministic core configuration must not create an infinite restart loop.

The production core build is still blocked by M0 provenance/reproducibility work, so lifecycle policy needs to be testable without selecting or downloading an unapproved binary.

## Decision

`internal/core.Supervisor` is a runner-independent lifecycle state machine. It owns exactly the `Process` returned by its injected `Runner` and is the only component that calls `Wait` for that process.

The default policy follows the initial bounds in `docs/plan.md`:

- exponential restart delay beginning at 1 second;
- delay capped at 60 seconds;
- a 10 minute failure window;
- circuit open after 5 failures in that window;
- graceful-stop timeout of 10 seconds, followed by a force-kill of that same owned process.

The supervisor only treats process start failure or process exit as restart input. Network reachability, subscription refresh failure, DNS reachability, or an observation-channel error are not process-restart signals.

An explicit stop clears the desired-running intent and cancels pending restart backoff. A stopped core therefore stays stopped. A circuit-open state requires an explicit operator reset; reset does not start the core by itself.

## Process contract

A runner returns a process handle with `PID`, `Wait`, `Terminate`, and `Kill`. The supervisor never discovers a process by listening port and never sends a signal to a PID it did not obtain from the runner handle.

`Terminate` requests graceful shutdown. If the process has not exited by the configured stop timeout, the supervisor calls `Kill` on the same handle. The wait path remains owned by the supervisor, preventing double reaping.

## Current integration boundary

This ADR does **not** approve a core binary and does not make `core_supervision` a product capability yet. The daemon continues to report that capability as false until all of the following are wired and tested together:

1. a provenance-checked executable runner tied to the locked core artifact;
2. deterministic generated configuration and pre-start validation;
3. authenticated local core control/health checks;
4. generation/apply-journal transitions around activation and rollback;
5. process identity and recovery checks after daemon restart.

No code in this supervisor downloads a core, chooses a `latest` version, or treats the inspected Clash `PUT /configs` response as a full reload mechanism.

## Consequences

- Restart behavior is independently unit-testable with fake processes.
- TUI lifetime cannot become restart ownership.
- Deterministic failures become visible `failed`/circuit-open states instead of restart storms.
- The real executable runner remains an M1 integration task and cannot bypass M0 core provenance blockers.
