# Upstream audit and M0 blockers

This file records implementation-relevant facts that must remain explicit while M0 is open. It does not approve any upstream binary for production use.

## Fixed source baselines

| Component | Reference |
| --- | --- |
| Karing application source | `KaringX/karing@9d28b22fbbcca5818d147629aae151d49d4dcb7b` |
| M1 standalone core baseline | `KaringX/sing-box@beddeababcc71dfb0c78124598b13341c06c69fb` (`karing_v1.13.19`) |
| Rejected 1.14 M1 candidate | `KaringX/sing-box@9f020fcefd4c9655689d503abd11572f31365b5a` (`karing_v1.14.0`) |
| CN preset source | `assets/datas/preset/cn.json` from the fixed Karing application commit |

## Confirmed blockers and constraints

### 1.14 is not a reproducible standalone baseline at the inspected commit

Four project provenance runs exercised `karing_v1.14.0@9f020fce...`. The first runs proved that the active local sibling replacements cannot be reconstructed from the older pseudo-version comment commits: the core consumes newer APIs such as `sing/common/cleanup`, `sing-tun/gtcpip`, and `sing-quic/hysteria2/realm`.

A second pass resolved sibling snapshots from the documented KaringX branches and added the build tags that the fork's source itself requires. That moved compilation forward but still failed in the fixed core tree on mutually inconsistent APIs, including:

- Clash API files referring to the removed/renamed traffic manager implementation;
- `api_extension_karing.go` requiring `dns.ClientOptions.IndependentCache` after the candidate removed that field;
- QUIC call signatures that do not match the selected fork dependency;
- a WireGuard composite literal incompatible with the candidate's `DialerOptions`.

The KaringX repository exposes no successful Actions run for this branch that can close those contradictions. M1 therefore does not patch the 1.14 source locally. It remains a tracked upgrade target.

### M1 baseline moves to the stable 1.13.19 fork head

`karing_v1.13.19@beddeaba...` keeps the inspected KaringX dependencies as fixed remote pseudo-version replacements in `go.mod`, avoiding the live local-workspace problem in 1.14. The corresponding source also retains the internally consistent Clash traffic manager imports and DNS client fields needed by the Karing extensions.

At this candidate, the upstream build workflow pins Go **1.25.12**. The project reference build uses:

- Linux pure-Go (`CGO_ENABLED=0`);
- `release/DEFAULT_BUILD_TAGS_OTHERS` unchanged as the base;
- `release/LDFLAGS` unchanged;
- appended `with_karing,with_shadowsocksr`, required by the fork's own guarded packages;
- a fixed linker-injected version string instead of the Makefile's `read_tag@latest`.

`scripts/verify-core-build.sh` and `.github/workflows/core-provenance.yml` build amd64 and arm64 but do not publish artifacts. Provenance run #5 successfully produced both binaries, but source inspection then found a disqualifying Linux behavior under `with_karing`: `cmd/sing-box/extension_process_linux.go` enumerates processes with the same executable basename and calls Terminate/Kill on them from the CLI pre-run path. Those hashes are retained only as rejected evidence. The safe reference build now forbids `with_karing`, keeps the upstream base tags, appends only `with_shadowsocksr`, and reruns ordinary-user `version/check/run`, authenticated loopback Clash API, three fixed Mixed listeners, and clean shutdown. `build_approved` remains false until that safe path passes.

### Clash API full reload remains untrusted

The daemon must not infer successful full configuration activation from a `PUT /configs` status code alone. Managed application continues to use controlled candidate activation, local behavior verification, and rollback.

### CN preset evidence is fixed but not yet vendored

The fixed Karing CN preset contains 28 ordered groups. The project will vendor the exact source plus provenance in M2, after rule-resource and licensing closure is documented. It must not be replaced by a two-rule "CN direct / otherwise proxy" shortcut.

### M1 standalone core build is approved

Core-provenance run **#9** completed successfully on native Linux runners for both supported architectures.

| Architecture | SHA-256 |
| --- | --- |
| linux/amd64 | `829452e2927ab8a9836fec398d5bbade259b3837df774c53afb3ec4eb20a1569` |
| linux/arm64 | `77a46000241540067c903bbfdf7c320638066abb9888635bc7a3f1810ee4b512` |

The run rebuilt the project-owned `cmd/karing-tui-core` entrypoint over the exact locked KaringX/sing-box 1.13.19 library baseline and verified the recorded hashes. On native amd64 and arm64 runners it also passed ordinary-user `version`, config `check`, `run`, Bearer-authenticated Clash `/version`, SOCKS5 negotiation on all three configured Mixed listeners, and SIGTERM shutdown.

This approval is intentionally narrow. It approves the reproducible standalone Linux core artifact contract, not production daemon wiring, not the upstream Karing CLI, not 1.14, and not any TUN/system-proxy/route-takeover behavior.


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
- an apply coordinator with bounded check/activate/verify/rollback steps, immutable previous-generation rollback, and fault-injection tests for check/start/verify/commit/rollback failures;
- immutable on-disk generation config staging under the private state directory, with SHA-256 identity, 0600 files, 0700 directories, symlink/ownership checks, atomic publish, fsync, and refusal to overwrite an existing generation with different content;
- a generation-bound verified runner that accepts only private absolute config paths, re-verifies the locked core before each `run`/`check`, and passes the exact immutable generation path to the project-owned core entrypoint;
- a ManagedCore adapter that composes durable applied-generation lookup, immutable staging, verified `check/run`, bounded Supervisor restart, local authenticated health verification, rollback, explicit stop-intent preservation, and controlled circuit reset for operator-driven apply/rollback;
- a context-aware daemon operation gate that serializes future lifecycle/apply/recovery mutations, reports the active operation, releases after errors, and lets queued callers cancel without altering the running operation;
- startup interruption recovery that blocks new applies when core reconciliation could be required;
- a bounded core lifecycle state machine with explicit stop intent, exponential restart backoff and a failure-window circuit breaker;
- a Linux process-group runner that rejects unsafe executable paths, plus readiness gating and fixed-capacity stdout/stderr buffers; concurrent bounded-log writes are exercised under the CI race detector;
- an authenticated loopback-only Clash `/version` probe validated against the fixed KaringX/sing-box source, including Bearer auth and the expected `sing-box`/`premium`/`meta` response contract;
- a first-class Rule/Direct/Selected inbound model with the plan defaults, strict loopback/distinct-port validation, and a SOCKS5 greeting probe for expected Mixed listeners;
- a lifecycle coordinator that orders durable start/stop intent before supervisor actions and blocks restored starts while apply recovery is unresolved;
- secure opt-in runtime options that accept only an absolute SHA-pinned core path, create a private random loopback control secret, and reject control-port collisions;
- conditional local lifecycle API/CLI wiring that starts the supervisor engine, restores persisted intent, serializes start/stop operations, and reports real core state/PID/circuit diagnostics;
- explicit capability flags that keep incomplete M1/M2 features false;
- a restricted sing-box import guard that rejects TUN, TPROXY, redirect, `auto_route`, `auto_redirect`, and `set_system_proxy=true` so imported configs cannot silently mutate Linux proxy settings;
- a sample `systemd --user` service that keeps the daemon in the foreground.

Still open before M1 can be called complete: deterministic restricted native-config compilation with correct Rule/DIRECT/CurrentSelected semantics, composing/exposing managed apply only through that compiler boundary, route-behavior verification beyond listener/control readiness, generation retention/garbage collection, database online-backup integration, packaging/license closure for core distribution, and process-level crash/power-loss fault injection across the real external core/SQLite boundary.
