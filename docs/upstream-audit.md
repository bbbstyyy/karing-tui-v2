# Upstream audit and M0 blockers

This file records implementation-relevant facts that must remain explicit while M0 is open. It does not approve any upstream binary for production use.

## Fixed source baselines

| Component | Reference |
| --- | --- |
| Karing application source | `KaringX/karing@9d28b22fbbcca5818d147629aae151d49d4dcb7b` |
| KaringX/sing-box candidate | `KaringX/sing-box@9f020fcefd4c9655689d503abd11572f31365b5a` (`karing_v1.14.0`) |
| CN preset source | `assets/datas/preset/cn.json` from the fixed Karing application commit |

## Confirmed blockers and constraints

### Core build is not yet reproducible from the candidate repository alone

The fixed KaringX/sing-box `go.mod` declares Go `1.25.5`, but also contains multiple local sibling replacements such as `../../KaringX/sing`, `../../KaringX/sing-quic`, `../../KaringX/quic-go`, `../../KaringX/sing-tun`, `../../KaringX/wireguard-go`, and `../../KaringX/tailscale`.

Until every required sibling source revision, build tag, tool version and artifact hash is fixed and verified, `resources/core.lock.json` keeps `build_approved=false`. The daemon must not download an arbitrary "latest" core to work around this.

Source: <https://github.com/KaringX/sing-box/blob/9f020fcefd4c9655689d503abd11572f31365b5a/go.mod>

### Clash API `/configs` is not a full hot-reload contract at this baseline

At the fixed candidate, the relevant handler accepts PATCH mode changes while the update handler for PUT returns `204 No Content` without applying a new full configuration. A successful HTTP status therefore cannot be used as proof that a generated configuration became active.

Source: <https://github.com/KaringX/sing-box/blob/9f020fcefd4c9655689d503abd11572f31365b5a/experimental/clashapi/configs.go>

### CN preset evidence is fixed but not yet vendored

The fixed Karing CN preset contains 28 ordered groups. The project will vendor the exact source plus provenance in M2, after the rule resource and licensing closure is documented. Do not replace it with a two-rule "CN direct / otherwise proxy" shortcut.

Source: <https://github.com/KaringX/karing/blob/9d28b22fbbcca5818d147629aae151d49d4dcb7b/assets/datas/preset/cn.json>

## Management-plane toolchain and state dependency

The management-plane Go version is pinned to `1.27.1` in `resources/toolchain.lock.json`. The core remains independently pinned to the version declared by its candidate source until its build process is made reproducible.

The state layer uses `modernc.org/sqlite v1.60.1`, a CGO-free SQLite driver, and explicitly pins `modernc.org/libc v1.77.1`, the version required by that driver release. The driver is BSD-3-Clause; the dependency selection is recorded in `resources/dependencies.lock.json`. This choice does not alter the still-open project/upstream/resource license closure.

## Implemented foundation

Implemented now:

- secure XDG runtime path resolution;
- single-user Unix socket daemon with `0600` socket permissions;
- versioned `/v1/status`, `/v1/capabilities`, and `/v1/healthz` endpoints;
- CLI status/capability clients;
- a private SQLite database with schema migration metadata, WAL mode, full synchronous durability and startup quick-check;
- immutable candidate generations with SHA-256 identity and a 64 MiB compiled-config ceiling;
- confirmed revision, applied generation, last-known-good generation, recovery-required state, and persisted core desired state (default `stopped`);
- a one-at-a-time apply journal with prepare/activate/verify/rollback/commit phases;
- startup interruption recovery that blocks new applies when core reconciliation could be required;
- a bounded core lifecycle state machine with explicit stop intent, exponential restart backoff and a failure-window circuit breaker;
- a Linux process-group runner that rejects unsafe executable paths, plus readiness gating and fixed-capacity stdout/stderr buffers;
- an authenticated loopback-only Clash `/version` probe validated against the fixed KaringX/sing-box source, including Bearer auth and the expected `sing-box`/`premium`/`meta` response contract;
- a first-class Rule/Direct/Selected inbound model with the plan defaults, strict loopback/distinct-port validation, and a SOCKS5 greeting probe for expected Mixed listeners;
- a lifecycle coordinator that orders durable start/stop intent before supervisor actions and blocks restored starts while apply recovery is unresolved;
- explicit capability flags that keep incomplete M1/M2 features false;
- a restricted sing-box import guard that rejects TUN, TPROXY, redirect, `auto_route`, and `auto_redirect` inbounds;
- a sample `systemd --user` service that keeps the daemon in the foreground.

Still open before M1 can be called complete: exposing the lifecycle coordinator through explicit daemon API commands, wiring it and the implemented probes to a provenance-approved locked core artifact, compiling the three modeled inbounds with correct Rule/DIRECT/CurrentSelected semantics, deterministic restricted native-config compilation, local proxy-behavior verification beyond the control API, generation retention/garbage collection, database online-backup integration, and fault-injection coverage across the external core/SQLite transaction boundary.
