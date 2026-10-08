# ADR 0072: Bounded read-only Bubble Tea terminal client

## Status

Accepted as an M4 incremental implementation. Not a complete TUI.

## Context

The daemon already owns persisted configuration, profile sources, node snapshots, the managed core and recovery. Putting any of these responsibilities inside an interactive terminal process would violate long-running lifecycle and fail-closed constraints in `docs/plan.md`.

## Decision

Pin the **v1** Bubble Tea API at `github.com/charmbracelet/bubbletea@v1.3.10` (MIT). Do not mix the v2 module or major-version API. The terminal command `karing-tui tui` is a disposable, read-only client. It uses only existing versioned daemon Unix-socket APIs to render Dashboard, Profiles and Nodes.

The model issues bounded asynchronous commands, never performs I/O in `Update`/`View`, and cancels pending requests when the TUI exits. Manual `r` initiates reload; no background polling or unbounded event queue is introduced. Each response is tagged with a monotonically increasing request sequence so late replies cannot overwrite newer state.

The UI caps the displayed profile list at 200 and the node API page size at 20, with a bounded offset. It projects source records into a small allowlisted metadata model and explicitly discards raw core-error strings; neither profile source locations nor raw daemon/core failure strings may be retained as display state or enter the screen. Every displayed line strips control, bidi formatting and line separator characters, then truncates to the terminal viewport. The UI is ASCII by default and tolerates Chinese and narrow terminals.

`q` and Ctrl-C close only the terminal client. The UI exposes **no mutating API** and cannot stop the daemon/core, commit a declaration, or mutate routing/DNS. It does not add a subscription/ISP routing layer or any privileged/TUN feature.

## Validation

Unit tests cover status display without raw core errors, terminal-escape/bidi injection, Chinese width, narrow screens, page navigation, bounded lists, asynchronous request timeouts and stale-response suppression. CI must run Go format, vet, full tests, race tests and build, plus existing managed-core integration.

## Remaining M4 work

- Display routing and DNS with original layer/provenance semantics and explicit unknowns.
- Add user-confirmed, revision/CAS-protected selector and overlay mutations without applying core inadvertently.
- Add backup/restore, detailed controlled diagnostics, connection attribution, and layout/terminal compatibility fixtures.
- Keep CN offline resource licensing/closure and complete protocol/DNS behavior as release blockers.
