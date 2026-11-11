# ADR 0010: Gate managed core runtime behind verified deployment configuration

- Status: Accepted
- Date: 2026-10-05

## Context

The M1 core artifact is reproducibly buildable and SHA-pinned, and the daemon already has a supervisor, lifecycle coordinator, immutable generation store, local health probes, and apply transaction skeleton. Packaging and redistribution are not closed yet, so the daemon cannot assume that a core binary is installed at a global path.

Starting an arbitrary path from persistent user configuration would also create a code-execution boundary that the product does not need.

## Decision

Core runtime wiring is opt-in through deployment environment, not through imported proxy configuration.

`KARING_TUI_CORE_PATH` may point to one absolute executable path. The daemon accepts it only if `internal/coreartifact.Verify` proves the opened non-symlink file has safe ownership/mode and exactly matches the approved architecture SHA-256. The same verifier runs again before every core start and restart.

If the variable is absent, the management daemon starts without a core runtime. If it is present and verification fails, daemon startup fails closed.

The three initial Mixed inbound ports remain the domain defaults `2080/2081/2082`. The core control API defaults to loopback port `3057`; deployment may override only the port, and collisions with proxy ports are rejected.

A random 32-byte control secret is created once under the private state directory, persisted as 64 hexadecimal characters in a `0600` regular file, opened with `O_NOFOLLOW`, and never exposed through status, URLs, process arguments, or normal logs.

## Runtime lifecycle

When configured, the daemon starts the supervisor engine and waits on an explicit readiness barrier before serving lifecycle commands. Persisted lifecycle intent is restored asynchronously so a restore error does not make the management API unavailable for diagnosis.

`POST /v1/core/start` and `POST /v1/core/stop` are serialized through the daemon operation gate. Start/stop persistence ordering remains owned by `LifecycleCoordinator`. Status reports configured state, supervisor state, PID, failure count, circuit state, active operation, and bounded restore/supervisor errors.

If the supervisor engine itself exits unexpectedly while the daemon is otherwise healthy, the daemon exits with failure so the external user-service supervisor can restart the management service.

## Non-goals

This does not expose managed configuration application. `managed_apply` remains false, and lifecycle start can only use the confirmed applied generation already recorded in durable state.

The runtime configuration cannot enable TUN, system proxy changes, arbitrary executables, LAN control endpoints, or a different unpinned core build.


## Real-core transaction integration

The managed-core integration workflow now builds the approved artifact and exercises the daemon runtime against it. Readiness is treated as a bounded startup condition: transient loopback connection failures are retried inside the supervisor's readiness deadline, while deterministic authentication or protocol-contract failures fail immediately.

The integration flow verifies:

- first candidate check/activate/verify/commit while desired state is stopped, followed by restoration to stopped;
- explicit lifecycle start of the committed generation;
- process-group SIGKILL followed by bounded supervisor restart;
- invalid candidate rejection before activation without disturbing the running generation;
- second valid generation replacement while desired state is running;
- explicit stop persistence with no restart afterward.

The server runtime now owns both lifecycle and apply coordinators behind the same operation gate. This closes an internal composition gap, but it does not expose a public raw sing-box apply endpoint. `managed_apply` remains false until deterministic domain compilation and a versioned apply API are implemented.
