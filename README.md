# karing-tui-v2

Linux terminal-oriented Karing reimplementation, following [`docs/plan.md`](docs/plan.md).

> Status: early development. The daemon/API foundation exists, but the proxy core, SQLite transaction layer, five-layer routing compiler, CN preset runtime, subscriptions, and TUI are **not** implemented yet.

## Non-negotiable scope

- Linux, ordinary user permissions.
- No TUN, TPROXY, redirect, firewall manipulation, route takeover, or automatic privilege escalation.
- Karing-style multi-layer routing will be preserved as **custom → GeoSite → GeoIP → ACL → FINAL**. Subscription/ISP routing layers are intentionally excluded.
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

## Build and test

The management-plane toolchain is pinned in [`resources/toolchain.lock.json`](resources/toolchain.lock.json).

```bash
make fmt-check
make vet
make test
make build
```

## systemd user service

A sample unit is in [`packaging/systemd/karing-tui-v2.service`](packaging/systemd/karing-tui-v2.service). It deliberately runs the daemon in the foreground and does not require network availability to start.

## Upstream/core status

The candidate core is **not yet approved for production builds**. See [`docs/upstream-audit.md`](docs/upstream-audit.md) and [`resources/core.lock.json`](resources/core.lock.json) for the current M0 blockers, including local sibling `replace` directives in the fixed KaringX/sing-box source and the non-reload behavior of the inspected `/configs` PUT handler.

## License

Project licensing and upstream/resource license closure are still M0 work. Do not redistribute upstream code or rule assets from this repository until the relevant license audit is complete.
