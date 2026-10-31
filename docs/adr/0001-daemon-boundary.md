# ADR 0001: Keep the management daemon independent from TUI and core

- Status: Accepted
- Date: 2026-10-04

## Context

The project plan requires long-running proxy service behavior even when a terminal UI exits, and it forbids making the TUI the owner of persistent state or the proxy core process.

## Decision

The first executable exposes a foreground `daemon run` command and clients communicate with it through a versioned HTTP API on a per-user Unix socket. The TUI will be another client of this API. The proxy core remains a separate process supervised by the daemon once the M0 core build/provenance blockers are resolved.

The daemon does not daemonize itself. Production use is expected to put it under `systemd --user` or another explicit supervisor.

## Security constraints

The daemon refuses an implicit globally writable `/tmp` socket fallback. It requires `XDG_RUNTIME_DIR` or an explicit `KARING_TUI_RUNTIME_DIR`, verifies current-UID ownership and rejects group/other-writable runtime directories. The socket itself is mode `0600`.

## Consequences

- Closing a future TUI will not imply stopping the daemon.
- API compatibility can evolve independently from terminal rendering.
- Core restarts and configuration transactions can be centralized later.
- Environments without a safe runtime directory fail explicitly instead of silently weakening local API protection.
