# karing-tui-v2

Linux terminal-oriented Karing reimplementation, following [`docs/plan.md`](docs/plan.md).

> Status: early development. The daemon/API, durable SQLite generation/apply journal, approved reproducible Linux core build, bounded supervisor, secure runtime core options, and conditional lifecycle API now exist. The deterministic routing/config compiler, managed apply API, CN preset runtime, subscriptions, and TUI are **not** implemented yet.

## Non-negotiable scope

- Linux, ordinary user permissions.
- No TUN, TPROXY, redirect, firewall manipulation, route takeover, automatic system-proxy mutation, or automatic privilege escalation.
- Karing-style multi-layer routing will be preserved as **custom -> GeoSite -> GeoIP -> ACL -> FINAL**. Subscription/ISP routing layers are intentionally excluded.
- CN preset behavior must not be reduced to a two-rule shortcut.
- The daemon owns persistent configuration and future core supervision; the TUI is a disposable client.

## Current commands

```bash
karing-tui daemon run
karing-tui core start
karing-tui core stop
karing-tui status
karing-tui status --json
karing-tui capabilities
karing-tui version
```

The daemon requires a safe per-user runtime directory. Under a normal systemd user session, `XDG_RUNTIME_DIR` is already set. Tests and unusual supervisors may provide `KARING_TUI_RUNTIME_DIR`; the directory must be owned by the current UID and not writable by group/others.

## Persistent state and recovery

Authoritative state is stored under `XDG_STATE_HOME/karing-tui-v2/state.db`. The database is created as mode `0600` inside the private XDG state directory and uses SQLite WAL with full synchronous durability.

The state schema provides confirmed configuration revision, immutable candidate generations, SHA-256 identity, applied/last-known-good pointers, an apply journal, and a separately persisted core desired state. Preparing a candidate does not advance the confirmed revision. Only a verified commit may advance `config_revision` and the applied generation.

The core desired state defaults to `stopped` and changes only through explicit lifecycle commands; changing it does not consume a configuration revision. This preserves an explicit user stop across daemon restarts. If the daemon restarts after a candidate may already have reached core activation, persistent state becomes `recovery_required`. New apply operations must remain blocked until the future core supervisor re-establishes the confirmed applied generation. See [`docs/adr/0002-sqlite-generation-journal.md`](docs/adr/0002-sqlite-generation-journal.md).

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

## Core supervision boundary

The supervisor now has a Linux executable runner that creates a dedicated process group, signals only the process it owns, rejects relative/symlink/group-writable executables, waits for an injected readiness probe before entering `running`, and bounds stdout/stderr through fixed-capacity ring buffers. `internal/coreapi` also implements the pinned fork's authenticated `/version` readiness contract: loopback IP only, Bearer secret required, redirects and environment proxies refused, and the response body bounded before JSON validation. Restart policy remains 1/2/4/8... seconds up to 60 seconds with a five-failures-per-10-minutes circuit breaker.

`internal/domain` now also fixes the three P0 proxy entry roles as Rule / Direct / Selected, with plan defaults `127.0.0.1:2080`, `:2081`, and `:2082`. Ports must be non-zero and distinct, and bind addresses must remain loopback. The local health layer can verify all three expected Mixed listeners with a SOCKS5 greeting before readiness succeeds; it does not silently pick replacement ports.

`internal/domain.RoutingPlan` now fixes the routing layer skeleton as Custom -> GeoSite -> GeoIP -> ACL -> FINAL and uses typed route targets (DIRECT, BLOCK, CurrentSelected, Global URLTest, Custom URLTest, Specific Node). Disabled/NONE groups are represented by `Enabled=false`, never by a magic target, and the validator refuses duplicate/out-of-order group ordinals instead of silently sorting them. Enabled groups now also require an explicit boolean matcher AST (`atom/all/any/not`) with typed domain/suffix/keyword/regex, CIDR, rule-set, port, network, and optional process-name predicates. This deliberately avoids guessing that Karing's flat fields are globally OR or AND. `internal/compiler.CompileRouting` now deterministically lowers that explicit AST to the approved core's default/logical rule JSON without collapsing boolean structure. Runtime inbound tags are fixed as `in-rule`, `in-direct`, and `in-selected`: Direct and Selected receive explicit synthetic terminal routes first, while every five-layer rule and FINAL is scoped to `in-rule`. It preserves five-layer order, emits an explicit Rule-only FINAL action, collects rule-set/outbound/process dependencies in first-use order, and refuses group DNS bindings until their semantics are compiled instead of silently dropping them. `internal/compiler.TargetCatalog` now resolves typed targets without display-name coupling: DIRECT/CurrentSelected/GlobalURLTest have fixed internal tags, while Custom URLTest and Specific Node tags are SHA-256-derived from stable IDs with collision detection and deterministic diagnostics. Karing-field compatibility conversion, rule-set artifact closure, actual selector/URLTest/node outbound generation, DNS derivation, full config emission, and core-check integration remain pending, so `routing_ir` is still false.

`internal/daemon.LifecycleCoordinator` connects durable desired state to the supervisor contract with crash-oriented ordering: Start persists `running` before requesting a start; Stop persists `stopped` before stopping the process; restore refuses to start while apply recovery is unresolved. When a verified core path is explicitly configured, the daemon exposes this through `POST /v1/core/start` and `POST /v1/core/stop`, and status reports the real supervisor state/PID/circuit condition.

`internal/daemon.ApplyCoordinator` now provides the matching configuration transaction skeleton. Candidate config is durably prepared, checked before activation, then journaled through activation and verification. Only a verified candidate advances the confirmed revision/LKG. Any post-activation failure attempts the immutable previous generation; a failed rollback marks `recovery_required` and blocks further applies. Every external core operation and state step has a deadline, and cleanup uses a bounded detached context so caller cancellation cannot silently leave a safe-to-close prepared attempt active.

`managed_apply` stays false: the runtime can only start the already-confirmed applied generation. There is deliberately no endpoint that accepts arbitrary native sing-box JSON and bypasses the apply journal/compiler boundary.

### Optional managed-core runtime

Core supervision is opt-in until packaging/distribution is closed. Set `KARING_TUI_CORE_PATH` to an **absolute path** containing the exact approved `karing-tui-core` artifact for the current architecture. The daemon verifies that file against the locked SHA-256 before composing the runtime and again before every start/restart. An arbitrary executable with the same filename is rejected.

The three proxy entry defaults remain `127.0.0.1:2080/2081/2082`. The authenticated core control endpoint defaults to `127.0.0.1:3057`; `KARING_TUI_CORE_CONTROL_PORT` may select another non-conflicting port. The daemon creates a random 32-byte secret at `XDG_STATE_HOME/karing-tui-v2/core-control.secret` with mode `0600`; the secret is never placed in a URL, command line, status payload, or normal log.

If `KARING_TUI_CORE_PATH` is absent, the management daemon still runs normally and reports `core_configured=false`; lifecycle capability remains false. If it is present but fails identity/permission checks, daemon startup fails closed.


## systemd user service

A sample unit is in [`packaging/systemd/karing-tui-v2.service`](packaging/systemd/karing-tui-v2.service). It deliberately runs the daemon in the foreground and does not require network availability to start.

## Upstream/core status

The approved M1 standalone Linux baseline is `KaringX/sing-box@beddeababcc71dfb0c78124598b13341c06c69fb` from `karing_v1.13.19`, built through the project-owned minimal `cmd/karing-tui-core` entrypoint rather than the unsafe upstream Karing CLI. Core-provenance runs #9 and #10 reproduced the locked amd64/arm64 hashes on native runners and passed ordinary-user `version/check/run`, authenticated Clash `/version`, all three Mixed SOCKS5 listener probes, and clean SIGTERM shutdown.

Approved hashes:

- linux/amd64: `829452e2927ab8a9836fec398d5bbade259b3837df774c53afb3ec4eb20a1569`
- linux/arm64: `77a46000241540067c903bbfdf7c320638066abb9888635bc7a3f1810ee4b512`

The newer `karing_v1.14.0@9f020fce...` remains rejected as the M1 baseline because the inspected source/dependency snapshot is not build-closed. This is an explicit future upgrade target, not something patched silently into the stable baseline.

Build approval is narrower than product completion: core distribution/licensing, deterministic native-config compilation, managed apply, route-behavior fixtures, and long-running fault tests are still open. See [`docs/upstream-audit.md`](docs/upstream-audit.md), ADR 0009, and [`resources/core.lock.json`](resources/core.lock.json).

## License

Project licensing and upstream/resource license closure are still M0 work. Do not redistribute upstream code or rule assets from this repository until the relevant license audit is complete.
