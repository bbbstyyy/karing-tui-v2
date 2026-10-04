# karing-tui-v2

Linux terminal-oriented Karing reimplementation, following [`docs/plan.md`](docs/plan.md).

> Status: early development. The daemon/API and durable SQLite generation/apply journal foundation exist, but the proxy core supervisor, three proxy inbounds, five-layer routing compiler, CN preset runtime, subscriptions, and TUI are **not** implemented yet.

## Non-negotiable scope

- Linux, ordinary user permissions.
- No TUN, TPROXY, redirect, firewall manipulation, route takeover, or automatic privilege escalation.
- Karing-style multi-layer routing will be preserved as **custom -> GeoSite -> GeoIP -> ACL -> FINAL**. Subscription/ISP routing layers are intentionally excluded.
- CN preset behavior must not be reduced to a two-rule shortcut.
- The daemon owns persistent configuration and future core supervision; the TUI is a disposable client.

## Current commands

```bash
karing-tui daemon run
karing-tui status
karing-tui status --json
karing-tui capabilities
karing-tui version
```

The daemon requires a safe per-user runtime directory. Under a normal systemd user session, `XDG_RUNTIME_DIR` is already set. Tests and unusual supervisors may provide `KARING_TUI_RUNTIME_DIR`; the directory must be owned by the current UID and not writable by group/others.

## Persistent state and recovery

Authoritative state is stored under `XDG_STATE_HOME/karing-tui-v2/state.db`. The database is created as mode `0600` inside the private XDG state directory and uses SQLite WAL with full synchronous durability.

The first schema provides confirmed configuration revision, immutable candidate generations, SHA-256 identity, applied/last-known-good pointers, and an apply journal. Preparing a candidate does not advance the confirmed revision. Only a verified commit may advance `config_revision` and the applied generation.

If the daemon restarts after a candidate may already have reached core activation, persistent state becomes `recovery_required`. New apply operations must remain blocked until the future core supervisor re-establishes the confirmed applied generation. See [`docs/adr/0002-sqlite-generation-journal.md`](docs/adr/0002-sqlite-generation-journal.md).

## Build and test

The management-plane toolchain is pinned in [`resources/toolchain.lock.json`](resources/toolchain.lock.json). Direct state dependencies are recorded in [`resources/dependencies.lock.json`](resources/dependencies.lock.json).

```bash
make fmt-check
make vet
make test
make test-race
make build
```

CI runs with `GOTOOLCHAIN=local` on the pinned Go release and rejects an untidy `go.mod`/`go.sum`.

## systemd user service

A sample unit is in [`packaging/systemd/karing-tui-v2.service`](packaging/systemd/karing-tui-v2.service). It deliberately runs the daemon in the foreground and does not require network availability to start.

## Upstream/core status

The candidate core is **not yet approved for production builds**. See [`docs/upstream-audit.md`](docs/upstream-audit.md) and [`resources/core.lock.json`](resources/core.lock.json) for the current M0 blockers, including local sibling `replace` directives in the fixed KaringX/sing-box source and the non-reload behavior of the inspected `/configs` PUT handler.

## License

Project licensing and upstream/resource license closure are still M0 work. Do not redistribute upstream code or rule assets from this repository until the relevant license audit is complete.
