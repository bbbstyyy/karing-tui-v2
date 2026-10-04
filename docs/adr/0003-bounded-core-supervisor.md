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

1. binding the implemented Linux executable runner to a provenance-approved locked core artifact;
2. deterministic generated configuration and pre-start validation;
3. binding the implemented readiness gate to authenticated local core control/health checks;
4. generation/apply-journal transitions around activation and rollback;
5. process identity and recovery checks after daemon restart.

No code in this supervisor downloads a core, chooses a `latest` version, or treats the inspected Clash `PUT /configs` response as a full reload mechanism.

## Consequences

- Restart behavior is independently unit-testable with fake processes.
- TUI lifetime cannot become restart ownership.
- Deterministic failures become visible `failed`/circuit-open states instead of restart storms.
- The real executable runner remains an M1 integration task and cannot bypass M0 core provenance blockers.

## Implementation refinement: readiness and Linux process groups

The supervisor now supports an injected readiness probe with a bounded 10 second default deadline. A started process remains in `starting` until that probe succeeds. Readiness failure is counted against the same bounded failure budget as deterministic start failure; the unready process is terminated and reaped before retry.

The Linux `ExecRunner` starts the core in a dedicated process group and signals that owned group on graceful stop or force kill. It requires an absolute regular executable, rejects symlinks and executables writable by group/others, and does not search `PATH`.

Child stdout/stderr can be connected to fixed-capacity `RingBuffer` writers so log volume cannot cause unbounded daemon-memory growth. The daemon advertises these pieces separately from the still-false product-level `core_supervision` capability.


## Implementation refinement: authenticated local control probe

The fixed KaringX/sing-box source at `9f020fcefd4c9655689d503abd11572f31365b5a` places `GET /version` behind its Clash API authentication middleware. With a configured secret, the middleware accepts only `Authorization: Bearer <secret>`. The fixed handler returns JSON containing a `sing-box ...` version string together with `premium: true` and `meta: true`.

`internal/coreapi.ClashVersionProbe` implements that exact readiness contract. It requires a non-empty secret, accepts only an HTTP endpoint using a loopback IP literal and explicit port, disables environment proxy routing, refuses redirects, bounds the response body to 64 KiB, and validates the expected JSON shape before readiness can succeed.

This probe is intentionally local. It does not test general Internet access or node reachability, so an external network outage cannot by itself become a supervisor restart trigger. A later M1 integration step must still verify the three expected proxy listeners and required local proxy behavior before an apply is committed.
