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

`internal/domain.RoutingPlan` now fixes the routing layer skeleton as Custom -> GeoSite -> GeoIP -> ACL -> FINAL and uses typed route targets (DIRECT, BLOCK, CurrentSelected, Global URLTest, Custom URLTest, Specific Node). Disabled/NONE groups are represented by `Enabled=false`, never by a magic target, and the validator refuses duplicate/out-of-order group ordinals instead of silently sorting them. Enabled groups now also require an explicit boolean matcher AST (`atom/all/any/not`) with typed domain/suffix/keyword/regex, CIDR, rule-set, port, network, and optional process-name predicates. This deliberately avoids guessing that Karing's flat fields are globally OR or AND. `internal/compiler.CompileRouting` now deterministically lowers that explicit AST to the approved core's default/logical rule JSON without collapsing boolean structure. Runtime inbound tags are fixed as `in-rule`, `in-direct`, and `in-selected`: Direct and Selected receive explicit synthetic terminal routes first, while every five-layer rule and FINAL is scoped to `in-rule`. It preserves five-layer order, emits an explicit Rule-only FINAL action, collects rule-set/outbound/process dependencies in first-use order, and refuses group DNS bindings until their semantics are compiled instead of silently dropping them. `internal/compiler.TargetCatalog` now resolves typed targets without display-name coupling: DIRECT/CurrentSelected/GlobalURLTest have fixed internal tags, while Custom URLTest and Specific Node tags are SHA-256-derived from stable IDs with collision detection and deterministic diagnostics. `RuleSetCatalog` now closes referenced `geosite:/geoip:/acl:`-style sources against immutable revision inputs (`absolute source path + SHA-256 + source/binary format`), derives hashed runtime tags, and rewrites a deep copy of route rules so source references never leak into native `rule_set` fields. `coreartifact.Store.StageRuleSet` verifies the source through one non-symlink file descriptor, copies it into the daemon-owned private content-addressed store `core/rule-sets/sha256/<sha>.(json|srs)`, fsyncs publication directories, and detects later mutation. Compiler artifacts now distinguish `SourcePath` from `RuntimePath`; native local rule-set config cannot be emitted until every required artifact is rebound to its content-addressed runtime path. `internal/domain.SelectionPlan` and `internal/compiler.CompileSelectionGroups` now materialize the verified selector/URLTest layer: CurrentSelected can reference Specific Node, Global URLTest, or Custom URLTest; URLTest groups contain only Specific Node candidates, which structurally prevents selector cycles. Candidate order and explicit URL/interval/tolerance/idle-timeout values are preserved, unused URLTest groups are omitted from the runtime closure, missing groups/nodes fail closed, and CurrentSelected is emitted only after its URLTest dependencies. `internal/domain.Node` and `internal/compiler.CompileBasicNodeOutbounds` now provide the first protocol-safe node materialization slice: plain SOCKS4/4a/5 and HTTP CONNECT only, with validated bare server hosts, explicit non-zero ports, bounded credentials, stable `(ProfileID, NodeID)` identity, and no unknown-field passthrough. SOCKS4/4a are restricted to TCP; SOCKS5 may use TCP/UDP/both; HTTP is TCP-only by the approved core implementation. The compiler materializes only the Specific Node closure requested by selection/routing and rejects missing or duplicate node specs. TLS/headers/detour/UoT and the remaining proxy protocols are deliberately not modeled yet. `internal/compiler.CompileNativeConfig` now assembles the first deterministic approved-core envelope from the validated closure: three fixed Mixed inbounds with `set_system_proxy=false`, DIRECT + required IP-literal basic nodes + URLTest/selector outbounds, staged local rule-sets, ordered route actions, authenticated loopback Clash API, config SHA-256, and a resource/outbound/inbound manifest. It rejects domain-valued node servers until outbound/bootstrap DNS is compiled and verifies every route/group/rule-set reference before emission. The managed-core integration fixture now consumes this compiler path instead of hand-written sing-box JSON, so the approved core's real `check/run` exercises the emitted schema. `internal/domain.DNSPlan` now separates Bootstrap / Outbound / Direct / Proxy / Group / Fallback DNS roles, requires explicit UDP/TCP endpoints and ports, requires domain-valued DNS servers to name a Bootstrap profile, validates bootstrap references as a deterministic DAG, and validates enabled route-group DNS bindings against Group-role profiles. `internal/compiler.CompileOutboundDNS` now closes only the configured Outbound/Node DNS profile and its Bootstrap chain, emitting dependency-first UDP/TCP DNS server configs with stable hashed tags, explicit ports, the approved core's native direct dial path (no `detour` field), and explicit `domain_resolver` links for DNS-server hostnames. `BindNodeDomainResolver` deep-copies the basic node closure and assigns the Outbound resolver only to domain-valued node servers; IP-literal nodes remain resolver-free. `CompileNativeConfig` now inserts that closure into the native `dns` envelope and permits domain-valued proxy servers only when they bind the compiled Outbound resolver. To prevent this narrow resolver from becoming accidental target DNS, the root DNS final is an explicit Karing-fork `predefined` server returning `REFUSED`; unmodeled DNS therefore fails closed. Direct and Proxy target DNS are now explicit: DIRECT receives its configured resolver, Proxy DNS dials through CurrentSelected, and proxy-target rules receive guarded `resolve` actions before routing. Group DNS is also explicit: enabled groups preserve a `DNSProfileID`, active Group profiles are closed in routing order, each Group DNS profile declares its own independent detour target, and domain-preclassifiable groups expand to a Group-specific `resolve`/`route` pair. DNS-only detour targets are merged into the outbound dependency closure, so a resolver cannot reference an unmaterialized node or auto group. IP-/opaque-rule-set-dependent Group overrides fail closed rather than resolving with the wrong server. Fallback DNS semantics, encrypted transports, and classification DNS for IP-dependent rules remain pending. SQLite schema v3 now gives each generation optional immutable manifest/source-map blobs with their own SHA-256 identities. A real hand-built v2 SQLite fixture is migrated in tests to prove existing applied/last-known-good generations and running intent survive the additive upgrade without fabricated metadata. `PrepareApplyWithMetadata` requires both metadata documents to be bounded valid JSON, while the legacy `PrepareApply` path remains readable for pre-compiler generations. `compiler.NativeConfigArtifact` now serializes a deterministic snake_case manifest and route source-map, and the internal runtime can pass that artifact through `ApplyCoordinator.ApplyCompiled` into `PrepareApplyWithMetadata`. The legacy config-only apply path remains for compatibility, but the compiler-owned path now binds config, manifest, and source-map in one generation transaction. The real managed-core integration uses this strict artifact path for successful candidates and verifies persisted metadata before restarting the committed generation. Managed core generation loading now also verifies persisted compiler metadata when present: config/manifest/source-map hashes must match, the manifest schema/config identity must match the candidate, and every manifest rule-set must still be a private content-addressed file with the recorded SHA-256 before check/start/activate/rollback. Legacy generations without metadata remain readable for migration compatibility. Daemon declaration-state compilation is still pending, so `routing_ir`, `proxy_inbounds`, and `managed_apply` remain false. The exact Karing CN preset at `9d28b22f.../assets/datas/preset/cn.json` is now embedded as an immutable snapshot and loaded through `internal/preset`: all 28 groups, original ordering/names/emoji, six default-enabled groups, raw rule-set/domain/IP/package/process fields, and DIRECT/BLOCK/CurrentSelected defaults are preserved and strongly validated. The snapshot deliberately does not yet translate Karing's flat condition fields into the boolean matcher AST; that remains blocked on compatibility fixtures, so `cn_preset_snapshot=true` while `cn_preset=false`.

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


Direct/Proxy target DNS lowering is now implemented through explicit runtime resolver tags and fail-closed route resolution; Group/Fallback DNS remains pending.
