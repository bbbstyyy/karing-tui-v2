# karing-tui-v2

Linux terminal-oriented Karing reimplementation, following [`docs/plan.md`](docs/plan.md).

> Status: early development. The daemon/API, durable SQLite generation/apply journal, approved reproducible Linux core build, bounded supervisor, secure runtime core options, and conditional lifecycle API now exist. M2 routing/compiler primitives and M3 source/snapshot management exist, but broad subscription compatibility, the complete CN offline resource bundle, automatic profile-to-declaration promotion, and full TUI operation are **not** finished. A Bubble Tea TUI prototype provides read-only status/route/connection and DNS inspection, guarded CurrentSelected candidate switching, and confirmed node favorite/disabled overlays. Its Routing page now supports narrow compiler-previewed, explicitly confirmed **declaration-only staging** of group enabled, typed target and group-role DNS binding fields. The same bounded operation is available through `config route-preview` / `config route-stage` CLI. The TUI remains an incomplete editor and never implicitly applies a new core generation.

## Non-negotiable scope

- Linux, ordinary user permissions.
- No TUN, TPROXY, redirect, firewall manipulation, route takeover, automatic system-proxy mutation, or automatic privilege escalation.
- Karing-style multi-layer routing will be preserved as **custom -> GeoSite -> GeoIP -> ACL -> FINAL**. Subscription/ISP routing layers are intentionally excluded.
- CN preset behavior must not be reduced to a two-rule shortcut.
- The daemon owns persistent configuration and future core supervision; the TUI is a disposable client.

## Current commands

```bash
karing-tui daemon run
karing-tui tui
karing-tui core start
karing-tui core stop
karing-tui status
karing-tui status --json
karing-tui config apply-preview --out="$HOME/apply-receipt.json"
karing-tui config apply --receipt="$HOME/apply-receipt.json" --confirm
# Read-only confirmed generation and resource integrity report; NO restore performed
karing-tui config recovery-audit
karing-tui capabilities
karing-tui version
```

Run the daemon independently (for example as a systemd user service), then run `karing-tui tui` in an interactive terminal. On Dashboard (page `1`), press `a` to request a **compiler-only preview of the current unapplied declaration**. Review declaration/native SHA prefixes, current applied generation, selector revision, rules/DNS counts and the warning that applying may interrupt connections. Only `y` on the full-size confirmation screen sends a guarded apply; `Esc` cancels without a write. A terminal smaller than 64×16 cannot confirm. Status readback verifies generation/revision after the daemon finishes; a lost/invalid acknowledgement stays uncertain and is **never retried automatically**. `q` only exits the UI; if an apply already reached the daemon, it may finish after UI exit. See [ADR 0083](docs/adr/0083-dashboard-confirmed-apply-tui.md). `q` / Ctrl-C exits **only the TUI**. Press `1`/`2`/`3`/`4`/`5`/`6`/`7`/`8` for Dashboard / Profiles / Nodes / Route Probe / Selector / Connections / Routing / DNS, `Tab` to cycle, and `j`/`k` to select or scroll. On Profiles, Enter opens the selected profile's nodes; `n`/`p` pages nodes. On Nodes, `f`/`d` proposes a favorite/disabled toggle, `y` confirms, and Esc cancels. Node edits use the daemon's revision/CAS API and **do not** automatically update declarations or apply/restart the core. On Route Probe, `e` enters an ASCII hostname or literal IP, Enter requests a bounded local **applied-generation simulation**, `t` cycles Rule/Direct/Selected, and `r` repeats. The result shows layer/group/target and DNS-profile **binding**, not proof of observed DNS traffic or a verified live route; unknown rule-set matches remain unknown. Every TUI output line is sanitized and viewport-bounded. Page 5 shows selector intent/live readback and up to 128 typed members bound to the *applied* declaration. Choose with `j`/`k`, press `Enter` to propose, `y` to confirm, or `Esc` to cancel. Confirming sends `PUT /v1/selection/current/checked` with the captured CAS revision, generation and declaration hash; on conflict, 502 or timeout the TUI discards the proposal and GETs fresh state without retrying. A missing applied generation, incomplete/oversized candidate list or invalid binding leaves selection read-only. Page 6 shows bounded observed connections with simulated/unknown source attribution; `r` manually refreshes either page. Selector writes persist intent and update only CurrentSelected, with no automatic declaration apply or core restart; see [ADR 0076](docs/adr/0076-checked-current-selection-cas.md) and [ADR 0077](docs/adr/0077-confirmed-current-selection-tui.md). Pages `7` and `8` show bounded five-layer applied-declaration Routing and read-only DNS role/dependency inspection; `r` refreshes. Page `7` offers guarded single-field declaration staging only when the entire applied route list is available with no unapplied stage: `j/k` chooses an editable group, `e` previews an enabled toggle, `t` chooses a typed outbound target, and `g` chooses an existing group-role DNS profile or clears the binding. In a choice menu use `j/k` and Enter to **compiler-preview**, then `y` to **stage** or Esc to cancel. Built-in target choices include DIRECT, BLOCK, CurrentSelected and global URLTest; specific-node and custom URLTest targets are offered only if already referenced by the applied routing snapshot. DNS choices require an untruncated resolver list. FINAL and derived region rules are not directly editable. The compiler preview is **not** a core check; staging is **not** application or restart. CN preset and region-append origins and staged **unapplied** structure differences remain visible. Sensitive matcher values, DNS hosts and node credentials are omitted. Page `8` is still strictly read-only. Neither page claims actual packet/DNS-path observation, allows arbitrary matcher/DNS-server edits, or provides full apply/rollback controls. See [ADR 0078](docs/adr/0078-bounded-config-inspection-tui.md), [ADR 0080](docs/adr/0080-confirmed-route-enable-tui.md), and [ADR 0081](docs/adr/0081-route-target-dns-chooser.md). Full M4 operation and M2/M3 compatibility remain incomplete.

The daemon requires a safe per-user runtime directory. Under a normal systemd user session, `XDG_RUNTIME_DIR` is already set. Tests and unusual supervisors may provide `KARING_TUI_RUNTIME_DIR`; the directory must be owned by the current UID and not writable by group/others.

## Historical recovery staging status

The read-only `config recovery-audit` command now checks retained generations, immutable rule-set resources, and historical CurrentSelected/route-mode bindings. The storage layer additionally has an **internal-only** atomic historical candidate preparation primitive: it verifies committed history, exact revision/CAS bindings and quota, and records the historical source in SQLite schema v17. This **does not** apply or activate the historical core config, and no manual `restore` or `rollback` command/API exists. To enable it in the future, the daemon must recheck pinned rule resources and core binary, coordinate the apply gate, perform live core check/activate/verify and prove rollback-of-rollback with fault injection. See [ADR 0086](docs/adr/0086-atomic-historical-restore-preparation.md).

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

`internal/domain.RoutingPlan` now fixes the routing layer skeleton as Custom -> GeoSite -> GeoIP -> ACL -> FINAL and uses typed route targets (DIRECT, BLOCK, CurrentSelected, Global URLTest, Custom URLTest, Specific Node). Disabled/NONE groups are represented by `Enabled=false`, never by a magic target, and the validator refuses duplicate/out-of-order group ordinals instead of silently sorting them. Enabled groups now also require an explicit boolean matcher AST (`atom/all/any/not`) with typed domain/suffix/keyword/regex, CIDR, rule-set, port, network, and optional process-name predicates. This deliberately avoids guessing that Karing's flat fields are globally OR or AND. `internal/compiler.CompileRouting` now deterministically lowers that explicit AST to the approved core's default/logical rule JSON without collapsing boolean structure. Runtime inbound tags are fixed as `in-rule`, `in-direct`, and `in-selected`: Direct and Selected receive explicit synthetic terminal routes first, while every five-layer rule and FINAL is scoped to `in-rule`. It preserves five-layer order, emits an explicit Rule-only FINAL action, collects rule-set/outbound/process dependencies in first-use order, and refuses group DNS bindings until their semantics are compiled instead of silently dropping them. `internal/compiler.TargetCatalog` now resolves typed targets without display-name coupling: DIRECT/CurrentSelected/GlobalURLTest have fixed internal tags, while Custom URLTest and Specific Node tags are SHA-256-derived from stable IDs with collision detection and deterministic diagnostics. `RuleSetCatalog` now closes referenced `geosite:/geoip:/acl:`-style sources against immutable revision inputs (`absolute source path + SHA-256 + source/binary format`), derives hashed runtime tags, and rewrites a deep copy of route rules so source references never leak into native `rule_set` fields. `coreartifact.Store.StageRuleSet` verifies the source through one non-symlink file descriptor, copies it into the daemon-owned private content-addressed store `core/rule-sets/sha256/<sha>.(json|srs)`, fsyncs publication directories, and detects later mutation. Compiler artifacts now distinguish `SourcePath` from `RuntimePath`; native local rule-set config cannot be emitted until every required artifact is rebound to its content-addressed runtime path. `internal/domain.SelectionPlan` and `internal/compiler.CompileSelectionGroups` now materialize the verified selector/URLTest layer: CurrentSelected can reference Specific Node, Global URLTest, or Custom URLTest; URLTest groups contain only Specific Node candidates, which structurally prevents selector cycles. Candidate order and explicit URL/interval/tolerance/idle-timeout values are preserved, unused URLTest groups are omitted from the runtime closure, missing groups/nodes fail closed, and CurrentSelected is emitted only after its URLTest dependencies. `internal/domain.Node` and `internal/compiler.CompileBasicNodeOutbounds` now provide the first protocol-safe node materialization slice: plain SOCKS4/4a/5 and HTTP CONNECT only, with validated bare server hosts, explicit non-zero ports, bounded credentials, stable `(ProfileID, NodeID)` identity, and no unknown-field passthrough. SOCKS4/4a are restricted to TCP; SOCKS5 may use TCP/UDP/both; HTTP is TCP-only by the approved core implementation. The compiler materializes only the Specific Node closure requested by selection/routing and rejects missing or duplicate node specs. TLS/headers/detour/UoT and the remaining proxy protocols are deliberately not modeled yet. `internal/compiler.CompileNativeConfig` now assembles the first deterministic approved-core envelope from the validated closure: three fixed Mixed inbounds with `set_system_proxy=false`, DIRECT + required IP-literal basic nodes + URLTest/selector outbounds, staged local rule-sets, ordered route actions, authenticated loopback Clash API, config SHA-256, and a resource/outbound/inbound manifest. It rejects domain-valued node servers until outbound/bootstrap DNS is compiled and verifies every route/group/rule-set reference before emission. The managed-core integration fixture now consumes this compiler path instead of hand-written sing-box JSON, so the approved core's real `check/run` exercises the emitted schema. `internal/domain.DNSPlan` now separates Bootstrap / Outbound / Direct / Proxy / Group / Fallback DNS roles, requires explicit UDP/TCP endpoints and ports, requires domain-valued DNS servers to name a Bootstrap profile, validates bootstrap references as a deterministic DAG, and validates enabled route-group DNS bindings against Group-role profiles. `internal/compiler.CompileOutboundDNS` now closes only the configured Outbound/Node DNS profile and its Bootstrap chain, emitting dependency-first UDP/TCP DNS server configs with stable hashed tags, explicit ports, the approved core's native direct dial path (no `detour` field), and explicit `domain_resolver` links for DNS-server hostnames. `BindNodeDomainResolver` deep-copies the basic node closure and assigns the Outbound resolver only to domain-valued node servers; IP-literal nodes remain resolver-free. `CompileNativeConfig` now inserts that closure into the native `dns` envelope and permits domain-valued proxy servers only when they bind the compiled Outbound resolver. To prevent this narrow resolver from becoming accidental target DNS, the root DNS final is an explicit Karing-fork `predefined` server returning `REFUSED`; unmodeled DNS therefore fails closed. Direct and Proxy target DNS are now explicit: DIRECT receives its configured resolver, Proxy DNS dials through CurrentSelected, and proxy-target rules receive guarded `resolve` actions before routing. Group DNS is also explicit: enabled groups preserve a `DNSProfileID`, active Group profiles are closed in routing order, each Group DNS profile declares its own independent detour target, and domain-preclassifiable groups expand to a Group-specific `resolve`/`route` pair. DNS-only detour targets are merged into the outbound dependency closure, so a resolver cannot reference an unmaterialized node or auto group. IP-/opaque-rule-set-dependent Group overrides fail closed rather than resolving with the wrong server. Fallback DNS semantics, encrypted transports, and classification DNS for IP-dependent rules remain pending. SQLite schema v3 now gives each generation optional immutable manifest/source-map blobs with their own SHA-256 identities. A real hand-built v2 SQLite fixture is migrated in tests to prove existing applied/last-known-good generations and running intent survive the additive upgrade without fabricated metadata. `PrepareApplyWithMetadata` requires both metadata documents to be bounded valid JSON, while the legacy `PrepareApply` path remains readable for pre-compiler generations. `compiler.NativeConfigArtifact` now serializes a deterministic snake_case manifest and route source-map, and the internal runtime can pass that artifact through `ApplyCoordinator.ApplyCompiled` into `PrepareApplyWithMetadata`. The legacy config-only apply path remains for compatibility, but the compiler-owned path now binds config, manifest, and source-map in one generation transaction. The real managed-core integration uses this strict artifact path for successful candidates and verifies persisted metadata before restarting the committed generation. Managed core generation loading now also verifies persisted compiler metadata when present: config/manifest/source-map hashes must match, the manifest schema/config identity must match the candidate, and every manifest rule-set must still be a private content-addressed file with the recorded SHA-256 before check/start/activate/rollback. Legacy generations without metadata remain readable for migration compatibility. Daemon declaration-state compilation is still pending, so `routing_ir`, `proxy_inbounds`, and `managed_apply` remain false. The exact Karing CN preset at `9d28b22f.../assets/datas/preset/cn.json` is now embedded as an immutable snapshot and loaded through `internal/preset`: all 28 groups, original ordering/names/emoji, six default-enabled groups, raw rule-set/domain/IP/package/process fields, and DIRECT/BLOCK/CurrentSelected defaults are preserved and strongly validated. Each group also has a project-owned semantic ID (for example `cn.google`, `cn.openai`, `cn.domestic-direct`) that is independent of display text and ordinal, so future user overrides do not key off emoji/name or `cn-01`-style positions. The snapshot deliberately does not yet translate Karing's flat condition fields into the boolean matcher AST; that remains blocked on compatibility fixtures, so `cn_preset_snapshot=true` while `cn_preset=false`. The snapshot also exposes deterministic first-use rule-set closures: 66 unique references across all 28 groups for offline packaging, and 20 references for the six default-enabled groups. Disabled groups remain part of the package closure even though they are excluded from the initial active closure.

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


CN region auto-append is now modeled independently from the 28 custom preset groups. `domain.DefaultCNRegionAppendPlan()` fixes explicit region `cn`, independent GeoSite/GeoIP switches (both default true, matching the pinned Karing settings), and DIRECT intent; its resource refs are `geosite:cn` / `geoip:cn` according to those switches. It is intentionally not lowered into route rules yet because the exact runtime insertion/priority relative to user-selected GeoSite/GeoIP entries still requires a compatibility fixture.


CN preset user overrides now have a typed overlay model. Overrides are keyed by the project-owned stable CN group ID and may change only enabled state, typed route target, and optional DNS profile binding. Applying overrides preserves group order, display name/emoji, and a deep copy of the exact upstream match source; unknown IDs, duplicate overrides, invalid targets, and unsafe DNS profile identifiers fail closed.


SQLite schema v4 now separates immutable **declaration revisions** from compiled core generations. `CommitDeclaration` accepts bounded valid JSON with an explicit source label under CAS (`expected revision`), stores the exact bytes plus SHA-256 and parent revision, and advances a separate singleton declaration head. Historical declarations remain immutable/readable across reopen. This is intentionally distinct from `daemon_state.config_revision`, which continues to represent committed core apply generations.


Compiler-owned strict apply now requires declaration provenance on new native artifacts. The generation manifest records both the exact declaration revision and the SHA-256 of the declaration bytes. Compiler-only artifacts may remain unbound for isolated validation/tests, while `ApplyNativeArtifact` rejects unbound or partially bound provenance. Managed-core restart/rollback verification accepts historical manifests that predate declaration tracking, but validates any declaration provenance fields that are present. This closes the audit link between immutable declaration intent and immutable runtime generation without conflating declaration revision numbers with committed runtime config revisions.


`internal/daemon.DeclarationCompileCoordinator` now provides the immutable declaration-to-artifact trust boundary. It loads an exact positive declaration revision, recomputes and verifies the stored declaration SHA-256 before invoking any schema compiler, passes a defensive copy of the exact declaration bytes to the compiler engine, and then binds the resulting native artifact to that revision/hash. It intentionally does not apply the artifact; declaration compilation and runtime apply remain separate operations until the versioned declaration schema/compiler is wired into the daemon API.

## Profile management CLI (M3/M4 groundwork)

The daemon remains the sole state writer. Profile commands use the protected local Unix socket; they cannot modify the running core generation.

```sh
karing-tui profiles list --json
karing-tui profiles nodes my-profile --offset=0 --limit=100 --json
karing-tui profiles replace-overlay my-profile node-id \
  --expected-revision=0 --disabled=false --favorite=true \
  --alias='Local alias' --sort-rank=none
```

Listing commands exclude source locations, import source keys and proxy credentials. `replace-overlay` uses **full replacement**, not an implicit patch: all five state flags (revision, disabled, favorite, alias and sort-rank) must be explicitly provided to prevent accidentally resetting an existing preference. Read the node's current overlay revision with `profiles nodes` before editing. A stale revision or removed node is rejected; this does not auto-apply the declaration or restart the core. See [ADR 0067](docs/adr/0067-profile-node-management-api.md) and [ADR 0068](docs/adr/0068-profiles-cli.md).

## Source management CLI (incremental M3)

A source is configured through one strict JSON object piped on standard input (maximum 16 KiB). Do not pass token-bearing subscription URLs as command-line arguments.

```sh
# Prepare a private profile-source.json file with an editor, then:
karing-tui profiles put my-profile --expected-revision=0 --stdin < profile-source.json

# Observe the revision returned by put/list before triggering an explicit fetch:
karing-tui profiles refresh my-profile --expected-revision=1
karing-tui profiles nodes my-profile --json
```

Example source specification (placeholder URI, **not** an operational subscription):

```json
{
  "format": "sing-box",
  "location_kind": "url",
  "location": "https://example.invalid/my-subscription",
  "fetch": {"mode": "direct"},
  "enabled": true,
  "update_interval_seconds": 0
}
```

Use `uri-list` or `uri-list-base64` only for the implemented compatible subsets; unsupported protocol/transport fields reject the complete imported update. `--allow-empty` must be explicitly supplied before an empty accepted snapshot can replace a nonempty one. Refresh output omits imported credentials and raw untrusted diagnostic text. Refresh **does not** compile/apply a core config or change the active routing generation. See [ADR 0069](docs/adr/0069-profile-source-cli.md) and [compatibility matrix](docs/compatibility.md).

## Read-only snapshot-to-declaration preview (M3)

After a profile refresh produces an accepted snapshot, the Unix-socket daemon can examine how it would change an **existing** declaration:

`POST /v1/profiles/{profile_id}/declaration/preview`, with JSON `{"snapshot_id":123,"expected_declaration_revision":1}`.

The response reports a candidate SHA-256, stable overlay digest, counts of nodes added/removed/retained and whether the candidate was applied. Source keys, server passwords and complete candidate JSON are never included. Snapshot ID and base declaration revision must match current state; invalid selected-node references or unsupported formats fail closed.

A successful response is **schema-level, read-only evidence**, explicitly `core_validated=false` and `applied=false`. No declaration revision, rule resource or core generation is changed, and no core check is performed. See [ADR 0070](docs/adr/0070-read-only-profile-declaration-preview.md).


## Guarded route group and DNS-binding edits (staged, never automatically applied)

The first M4 structured edit supports **one** field per request on one existing route group: change its typed target, enable/disable it, or select/clear an existing **group-role** DNS profile. It does not edit DNS server host addresses, match expressions, group order/layer, CN preset resources, region-generated groups, or subscription/ISP routing. CN's original 28 groups can be changed via source-preserving `cn_preset.overrides` without modifying the pinned preset. Every candidate must satisfy the strict declaration compiler including local rule-set resource availability. This is not a real-core validation.

Use a private receipt file (the preview CLI creates it with `0600` and will not overwrite an existing path):

```sh
karing-tui config route-preview --layer=final --group=FINAL --target-kind=direct --out="$HOME/route-edit-receipt.json"
# Inspect the private receipt: previous/next target, candidate and native SHA-256, compiler_validated=true, applied=false
karing-tui config route-stage --receipt="$HOME/route-edit-receipt.json" --confirm
```

For ordinary groups, examples include `--layer=custom --group=work --enabled=false` and `--layer=custom --group=work --dns-profile-id=group-dns`; passing `--dns-profile-id=` clears that binding. Specific nodes use `--target-kind=specific_node --profile-id=P --node-id=N`; custom URLTest uses `--target-kind=custom_urltest --urltest-group-id=G`. Only one of `--target-kind`, `--enabled`, and `--dns-profile-id` is allowed per preview.

The daemon's `GET /v1/config/route-edit/context` exposes the expected declaration SHA/revision, config revision, applied generation (nullable) and CurrentSelected revision without returning raw declaration secrets. The `POST /v1/config/route-edit/preview` compiles a transient one-field candidate and returns only diff metadata and SHA-256 digests; the `POST /v1/config/route-edit/stage` requires those exact digests, re-runs the same strict compiler, checks all expected revisions and generation identity under the operation gate, then performs a SQLite declaration CAS. A conflicting commit or selector change produces HTTP 409, while failed validation/resource closure produces 422. On ambiguous stage timeout or transport loss, **read current declaration/status before taking action**; never blindly replay the receipt.

**Staging does not touch the core**, restart it, or change applied-generation state. Existing explicit declaration apply remains a separate, risk-bearing operation, with its usual journal/rollback guards. `compiler_validated=true` does **not** mean `core_validated=true` or that live DNS resolution took the declared path. See [ADR 0079](docs/adr/0079-guarded-route-dns-stage-cli.md). The full M4 Routing/DNS TUI editor, concrete per-rule DNS transport evidence and user-facing backup/restore remain open.

## Profile declaration preview CLI

To review the impact of the **current accepted snapshot** before any declaration edit, use the snapshot ID from `profiles refresh` and the current declaration revision from `status --json`:

```sh
karing-tui profiles preview my-profile --snapshot-id=123 --expected-declaration-revision=1
```

This command only requests the daemon's read-only preview. It returns credential-safe counts and SHA-256 digests. Its `applied` and `core_validated` fields are always false for this operation. It **cannot** promote a subscription snapshot to an active configuration.

## Explicit checked apply of the current staged declaration (disruptive)

After a profile or Routing edit has created a new **unapplied declaration revision**, inspect what will be compiled and applied:

```sh
karing-tui config apply-preview --out="$HOME/apply-receipt.json"
# Review the 0600 JSON receipt: declaration SHA/revision, expected config revision and generation,
# CurrentSelected revision, native config SHA-256, schema and resource counts.
# compiler_validated=true, core_validated=false, applied=false
karing-tui config apply --receipt="$HOME/apply-receipt.json" --confirm
karing-tui status --json
```

The second command is **explicitly disruptive**: the daemon strictly recompiles the current declaration, validates the exact receipt, performs managed-core check, activation, behavior verification and a durable config-generation commit. It may restart/replace the running core and interrupt existing connections. The CLI verifies the daemon acknowledgement against the receipt and reads back the new durable generation/revision before reporting success. Receipt files must be regular, owner-owned, private, bounded and not symlinks; no existing receipt is overwritten.

The guard rejects stale declaration content, changed config revision/generation, changed CurrentSelected intent or a new native SHA-256, and rejects an already-applied declaration. `config apply-preview` **does not** check or start the real core; no core changes happen until the deliberate `--confirm`. A timed-out/closed-client confirmation may have succeeded, failed or entered rollback; **never retry automatically**. Query `status --json` and investigate recovery state first. On check/activation/verification failure the pre-existing apply journal retains its transactional rollback semantics; this feature does not provide a manually selectable historical-generation rollback. Legacy `/v1/declaration/apply` can apply historical immutable revisions, but it is **not** the checked current-head UX described here. See [ADR 0082](docs/adr/0082-checked-current-declaration-apply-cli.md). Manual historical-generation rollback, consistent backups and real DNS detour observation remain outstanding.


## Historical generation recovery audit (read-only, no rollback)

Use `karing-tui config recovery-audit` after checking `karing-tui status --json`. The command reads `GET /v1/config/recovery/audit` over the private Unix socket. It enumerates at most twelve committed generation references from live and archived SQLite journal history, newest first. Entries distinguish whether the generation payload was pruned by retention, whether retained original native JSON/manifest/source-map and the exact immutable declaration still match SHA-256, and whether manifest-listed local content-addressed rule files still pass ownership/symlink and hash checks. Unconfirmed candidates are excluded. A read does not change the daemon, SQLite generations, desired core state or the currently running core.

**Important:** even an entry with `status=stored_integrity_verified_only` has `restore_ready=false`; the entire response has `restore_supported=false`. Hash integrity only proves stored bytes and referenced rule file checks at audit time. It is **not** proof that the historical generation is compatible with the currently running core, CurrentSelected state, routing mode, runtime resources or pending recovery journal. Metadata for already pruned generations is useful for diagnosis, but their native payload is not available. A concurrent apply/declaration change rejects the audit instead of returning a mixed view. **There is no new manual restore or rollback command.** Failure recovery continues to be owned by the existing apply coordinator. See [ADR 0084](docs/adr/0084-read-only-confirmed-generation-audit.md).


### Internal-only historical core compatibility check

In addition to the read-only `config recovery-audit`, the daemon now has an **internal-only**, operation-gated historical generation core-check path (ADR 0087). It strictly recompiles the historical declaration using the current compiler, selectors and control-plane parameters, verifies byte-identical native configuration/manifest/source-map and both fallback generations, atomically stages a new candidate, runs **core Check without activation**, and always aborts the prepared journal entry. A successful check is *not* a durable resource lease, activation permission, or rollback confirmation.

There is **no CLI, HTTP or TUI invocation** for this path. Manual restore remains unavailable, and `restore_supported=false` / `restore_ready=false` are unchanged. Live activation and verified rollback-of-rollback require further safety work. See [ADR 0087](docs/adr/0087-internal-historical-core-check.md).


Historical non-activating core checks additionally hold bounded, no-follow file descriptor pins for the target and BOTH applied/last-known-good rule resources. The check compares inode identity and original SQLite payloads after `core Check`, catching same-content file replacement or changes to fallback metadata that path-only SHA checks missed. These pins do **not** provide a durable activation lease or defend against every pathname ABA race. Manual restore remains unavailable; see [ADR 0088](docs/adr/0088-descriptor-pinned-historical-rule-resources.md).


### Historical dry-run storage reclamation (internal)

An internal historical core compatibility check uses an immutable SQLite candidate and never activates it. On completion, the daemon now performs a second bounded SQLite transaction to **archive its explicit prepared-only failure journal and reclaim only that candidate payload**. Current applied, LKG and confirmed generations are not globally pruned to make space. Repeated checks should not consume the generation payload quota; interrupted, active, rollback-failed, referenced or unmarked candidates are never reclaimed through this shortcut. Cleanup errors fail closed. See [ADR 0089](docs/adr/0089-reclaim-historical-check-candidates.md).

This is **not** a user-accessible restore operation: `restore_supported=false`, `restore_ready=false`, no manual rollback route, no core activation.


### Ephemeral isolated historical rule-resource copies

The internal-only historical core compatibility check now stages **independent private copies** of its pinned target/applied/LKG rule sets (up to 128 files / 128 MiB), rather than relying solely on shared source inode observation. Each source descriptor is reverified before/after the copy; every scoped file is SHA-256 checked, fsynced and owner-read-only. Copies are verified again after core `Check` and removed through an identity-checked cleanup. No native paths are rebound yet: **core Check still uses the original native rule paths**, so this is not an activation-ready isolated resource lease. A hard crash can leave a bounded orphan directory until safe scavenging exists. See [ADR 0090](docs/adr/0090-isolated-historical-rule-snapshots.md). Manual restore remains disabled.


### Crash-safe bounded cleanup for internal historical rule snapshots

Temporary historical rule-set snapshot scopes now hold Linux directory `flock` locks until cleanup. An internal, nonrecursive scavenger opportunistically removes only unlocked, private, bounded `.check-*` scopes before the next historical compatibility check, skipping another process's active scope. A short parent-directory lock prevents a scope from being reclaimed between creation and acquiring its own lock. Invalid/symlinked/unknown entries are not deleted; partial copies with safe `0600` permissions can be removed after an interruption. See [ADR 0091](docs/adr/0091-flock-guarded-orphan-snapshot-recovery.md).

This is not an activation-ready resource lease and does not rebind original native runtime paths. No manual restore API/CLI/TUI is exposed and `restore_supported=false` remains unchanged.


### Isolated native config check (internal-only)

Historical compatibility checks with local rule sets now **rebind only native `route.rule_set[].path`** to independently copied resources inside the bounded, flock-held snapshot scope. The original committed native JSON and hashes remain immutable. A separately SHA-256-bound, owner-read-only temporary JSON is consumed by the internal `ManagedCore.CheckIsolated`, which validates the **original** generation metadata but does not stage a replacement generation, bind the running core, activate, or commit. A core adapter without isolated check support is rejected rather than silently checking shared paths. The temporary config and copies are verified and reclaimed together; empty rule closures retain the ordinary strict Check. See [ADR 0092](docs/adr/0092-isolated-native-check-rebinding.md).

These checks **do not** enable manual historical restore or create cross-restart fallback leases; `restore_supported=false` and `restore_ready=false` remain in effect.

### M4 read-only recovery history in TUI

TUI page `9` (History, or Tab) requests the same bounded `GET /v1/config/recovery/audit` inventory as `config recovery-audit`. Press `r` to refresh and `j/k` to scroll. Both clients use a shared fail-closed response validator: unknown statuses, forged restore flags, contradictory evidence and unbounded results are rejected. Page exit cancels the in-flight read, and stale replies are discarded. Only numeric identifiers, allowlisted statuses and aggregate booleans are shown; no native JSON, rule paths or credentials are rendered. This is **not** a recovery action or an activation lease: manual restore remains disabled and history is never polled automatically. See ADR 0093.

### Internal M4 SQLite consistent snapshot prerequisite (not a backup command)

`storage.Store.CreateDatabaseSnapshot` now supports a bounded 30-second WAL-consistent private SQLite snapshot using `VACUUM main INTO` with exclusive 0600 output, a 0700 scope, source-page and final-byte budgets (768 MiB), SHA-256, read-only database `quick_check`, fsync and identity-checked cleanup. Regression tests cover committed WAL data, live changes after the snapshot, symlink/unsafe directory refusal, cancellation, quota failure, hardlinks and replacements. This method is intentionally **not exposed over CLI, API or TUI**: the database alone omits external rule-set/core resources and can contain credentials. It is not yet a portable or restorable backup, nor a cross-restart resource lease. Follow ADR 0094 for the missing integrity manifest, crash-safe cleanup and restore gates.


### M4 SQLite snapshot orphan recovery (internal only)

A private SQLite snapshot now holds a Linux directory `flock` throughout creation, validation and cleanup. A short parent-directory lock prevents a newly created scope being scavenged before its child lock is acquired. Before the next internal snapshot, `ReclaimOrphanedDatabaseSnapshots` scans at most 32 recognized `.sqlite-snapshot-v2-*` directories and removes only unlocked, single-file `0600` or empty partial scopes using inode checks and relative `unlinkat`; active scopes are skipped. Unknown/symlink/hardlinked/oversized entries and unsafe parents fail closed, without recursive deletion. Subprocess SIGKILL-style exit, active cross-process locks, concurrent creation and unsafe entries are tested (ADR 0095). Sensitive orphan scopes are not cleaned automatically at daemon startup or periodically. This remains an internal primitive, **not an exportable backup or restore capability**.

Older unleased `.sqlite-snapshot-*` directories are intentionally **not** scavenged: another running older binary might still own them. Their presence blocks new copies until safely resolved by an operator (ADR 0095).

### M4 snapshot-consistent rule-resource inventory (internal only)

`internal/backupclosure.Build` creates a private WAL-consistent SQLite copy and reads **all retained generation references only from that copy** (up to 32 generations), strictly verifying compiler-owned native config, source map, declaration provenance and exact local `route.rule_set` bindings. It deduplicates and pins at most 128 content-addressed rule sets / 128 MiB, independently copies them under existing flock-held ephemeral isolation, and rechecks both source inode identity and copied hashes. The in-memory, versioned SHA-256 inventory binds the database digest/size, generation identities/digests and relative rule filenames/hashes/sizes; it excludes credentials, raw native JSON and host paths, and always says `restore_ready=false`. Missing/changed resources, legacy unverifiable metadata, malformed native bindings and concurrent inode swaps fail closed. No core binary, durable archive, encryption, public API, CLI or TUI backup/restore exists. See ADR 0096.


### M4 approved-core private copy and v2 closure (internal only)

`backupclosure.BuildWithApprovedCore` extends the existing snapshot-consistent database/rule closure with an approved Linux sing-box executable identified **only** by the architecture-specific SHA-256 and commit in `resources/core.lock.json`. It retains a no-follow, single-link inode pin, independently copies the executable into the same flock-held rule-snapshot scope as an inert 0400 file, and verifies digest and identity before/after copying. The versioned v2 in-memory inventory adds only architecture, version, locked commit, SHA-256, length and a logical relative path; it contains no original core path or credentials and unconditionally declares `restore_ready=false`. Existing v1 `Build` remains the explicit rules-only variant. The bounded orphan scavenger understands the extra `core-<sha256>.bin` file; unfamiliar names still fail closed. Unit tests exercise inode swaps and tampering, and managed-core integration tests the real approved core. **No portable backup, encryption, cross-restart lease, launch from the copy, CLI/API or restore is enabled.** See ADR 0097.

## Internal encrypted archive retention boundary (M4)

The experimental internal sealed-archive writer uses a separate `.ktui-sealed-v2-*` namespace with Linux file/parent `flock` to protect active ciphertext generation. Only abandoned, verified v2 temporary ciphertext can be reclaimed; old unleased temporary names and ambiguous hard links require operator review. Completed `.ktbackup` files are never automatically pruned: the private archive folder has a fail-closed eight-file retention budget, plus 32 bounded temporary candidates. This does **not** provide a supported backup command, key custody, or restore capability. See [ADR 0100](docs/adr/0100-sealed-archive-leases-and-retention.md).

## Internal encrypted archive preflight (M4)

The internal `backupclosure.PreflightInertArchive` performs a read-only, full-authentication resource check followed by a whole-ciphertext replay before returning a redacted manifest compatibility summary. A caller may optionally compare digest counts with a separately pinned current closure, without exposing secrets or treating generation database IDs as portable identities. A matching approved-core architecture is **metadata-only** compatibility: no restore/import, backup key storage, SQLite relational restore validation, core activation or TUI/API recovery is enabled. See [ADR 0101](docs/adr/0101-authenticated-read-only-archive-preflight.md).

## Internal authenticated SQLite archive verification (M4)

After encryption and resource validation, internal recovery preflight now independently deserializes an authenticated SQLite payload of at most 64 MiB **in memory only**, runs SQLite integrity and foreign-key checks, verifies schema migrations and declarations, and binds historical compiler manifests, configurations and local rules to the archive inventory. It rejects cryptographically valid but relationally inconsistent snapshots, never writes a plaintext database, and never exposes a backup restore/activation API. `RestoreSupported=false` and `RestoreReady=false` remain mandatory. See [ADR 0102](docs/adr/0102-in-memory-authenticated-sqlite-logical-verification.md).

## Archive schema and profile consistency checks (internal, M4)

The internal preflight now compares the archive's entire SQLite schema against an independently migrated in-memory reference built from the pinned storage migrations, and audits profile snapshots, node payload hashes, subscription source metadata, overlay records and selection JSON under strict count and size limits. It returns only redacted metadata and rejects cryptographically valid archives with forged DDL or inconsistent profile state. **Not a recovery feature:** no data import or activation, no durable backup key custody, and no restore permission. See [ADR 0103](docs/adr/0103-archived-sqlite-schema-profile-audit.md).

## Internal encrypted restore candidate staging (M4)

A fully authenticated encrypted archive can now be copied into a separate, UID-private, strictly single-ciphertext candidate directory that remains on disk across process restarts. Linux directory `flock` prevents concurrent adoption; restart requires explicitly supplying the key and repeating the entire read-only SQLite/schema/profile preflight. Candidates are never automatically deleted, imported, activated, or granted restore authorization, and their files are not usable as plaintext database/core artifacts. The eight-scope retention bound fails closed. See [ADR 0104](docs/adr/0104-encrypted-restore-candidates.md).

## Read-only encrypted restore dry-run fence (M4)

Internal backup candidate inspection now cross-checks a single-transaction SQLite live-state fence (config revision, applied/LKG generation, declaration, selection and runtime intent) before and after two full encrypted-candidate authentications. It rejects active recovery/apply and injected concurrent state changes without creating a new generation or touching the proxy. Reports contain only stable IDs/hashes, not node/credential content; **they are not SQL write CAS receipts and never authorize restore**. See [ADR 0105](docs/adr/0105-inert-restore-readonly-cas-fence.md).

## Internal rollback-only restore write-intent guard (M4)

ADR 0106 adds a short SQLite write-intent **inspection** after full encrypted-candidate and live-state verification. It atomically checks committed config/selection/declaration hashes under a single-writer reservation, then rolls the no-value-change probe back before returning. Tests cover competing writers, cancellation, process death, stale candidate receipts and real approved-core integration. This **does not write or restore any backup**, hold an activation lease after return, or authorize a TUI/API/CLI restore. See [ADR 0106](docs/adr/0106-rollback-only-restore-write-cas.md).

## Crash-safe inert restore preparation journal (M4)

A new SQLite v18 table records only the identity of a fully verified encrypted candidate and a transaction-local, hash-bound live CAS baseline. The record is committed atomically without creating an apply attempt, replacing settings or activating sing-box. Pending rows survive SIGKILL and restart but never resume automatically; the key, candidate lock, and all integrity checks must be re-established, and abandon is explicit and non-destructive. Existing v17 encrypted archives remain readable for strict *preflight*, not import. No restore API or activation authorization exists. See [ADR 0107](docs/adr/0107-durable-inert-restore-journal.md).

## Journal-bound encrypted candidate re-acquisition (M4)

ADR 0108 extends the internal inert recovery preconditions with an exclusive live Linux ciphertext lease and an atomic rollback-only SQLite check of both the journal record and current configuration. After process death, a recorded candidate can only be examined by reacquiring the private directory lock, resupplying the key and re-running the full encrypted archive and SQLite/schema/profile checks. File inode replacement during a live lease is refused; failure never imports, activates or auto-deletes anything. This adds **no backup restore entrypoint**. [ADR 0108](docs/adr/0108-journal-bound-resource-lease.md) explains why a future transactional restore still requires durable resource pins and dual rollback.

## Internal stable-archive lifecycle gate (M4)

The private SQLite snapshot closure and encrypted-archive preflight now both refuse unsettled apply state (active apply or recovery required), pending inert restore rows, missing or uncommitted Applied/LKG history, and mismatched active revision. A committed generation must be evidenced by one matching terminal record in either the current journal or its compacted history. An empty initial database remains inspectable but offers no active generation. These checks inspect **the same immutable snapshot** as rule/metadata verification and do not touch the live daemon or core. They are non-activating and do not introduce user-facing backup/restore, plaintext import, or release readiness. See [ADR 0109](docs/adr/0109-stable-archive-lifecycle-attestation.md).

## Anonymous, non-executable encrypted-recovery resource probe (internal, M4)

ADR 0110 adds a journal-bound `InertRestoreResourceLease.ProbeAnonymousResources` that revalidates the encrypted candidate, then streams rule sets and (if present) the repository-approved Core into one private, **unnamed** Linux `O_TMPFILE` at a time, verifies SHA-256 and 0400 non-executable mode, and closes every FD before returning. The existing SQLite database is only inspected **in memory**, never extracted into a plaintext file. The caller supplies a separate private 0700 scratch directory; an unsupported filesystem fails closed instead of creating named plaintext. Failures, status changes and SIGKILL cannot create a resumable restore and do not modify the live core, LKG, declarations, selection or inert journal. A nameless temporary file does not guarantee forensic secure erasure of blocks; no credential-bearing SQLite is copied to temporary disk. This is not portable restore or a persistent resource pin; user-facing backup/restore commands and activation remain disabled, `RestoreSupported=false` and `RestoreReady=false`. See [ADR 0110](docs/adr/0110-anonymous-inert-restore-resource-probe.md).

## Internal portable restore-path preview (M4, ADR 0111)

Archived sing-box native generations can contain absolute paths from the original Linux state directory. An internal, journal-bound `PreviewPortableRulePaths` now re-authenticates the encrypted archive, independently validates its SQLite/schema/profile contents in memory, and checks all retained compiler-native `route.rule_set` bindings before computing a prospective content-addressed mapping to a different state root. It returns **only SHA-256 digests and bounded counts**, not decrypted JSON or credentials. It neither opens nor writes the target path and does not authorize trusting any destination files. A same-root preview preserves original native config hashes; missing rules or changed live state fail closed. Real Core integration proves preview without activation. This is **not** a restored state, schema migration, durable resource lease, rollback, or public backup/restore command. Actual import/activation stays disabled; `RestoreSupported=false` and `RestoreReady=false`. See [ADR 0111](docs/adr/0111-in-memory-portable-rule-path-preview.md).

## Internal destination filesystem preflight (M4, ADR 0112)

In addition to the authenticated memory-only path preview (ADR 0111), an internal `InspectPortableTargetRuleTree` can examine an **already existing**, private Linux destination rule tree. It walks each directory component using no-follow pinned file descriptors, checks owner-only modes, and independently verifies any existing content-addressed rule files by exact size/hash, no hardlinks and no execute permission. Absent rule files are counted but **not installed**. Symlinks, stale inodes, corrupt files, relaxed permissions and concurrent journal/live configuration changes cause refusal. This is bounded **read-only** inspection: all descriptors close at return; the daemon's current state, secrets, rules and core stay untouched. It is not safe to reuse the result as a later filesystem lease, does not authorize import or activation, and user-facing backup/restore remains disabled. See [ADR 0112](docs/adr/0112-readonly-target-rule-tree-inspection.md).

## Pinned anonymous restoration resources (internal M4, ADR 0113)

The encrypted-candidate recovery chain now supports a bounded, **in-process only** rule/Core resource lease. Instead of only verifying that each file can be briefly copied (ADR 0110), `PinAnonymousRestoreResources` retains verified, unlinkable Linux `O_TMPFILE` descriptors until `Close`. A separate `Revalidate` checks every retained inode/hash plus the encrypted source, journal and current live state again. Only one such bundle is allowed per live candidate lease to prevent descriptor/disk growth. This does not publish rules, create executable files, decrypt SQLite to disk, run sing-box or alter Applied/LKG. Restart invalidates every FD; real durable import, same-transaction restore CAS and two-level rollback remain unfinished. **Backup/restore endpoints remain disabled** and both restore-permission flags are false. See [ADR 0113](docs/adr/0113-revocable-anonymous-restore-resource-leases.md).

## Inactive rule-only bundle preparation (M4, ADR 0114)

The authenticated recovery chain now has an internal **rules-only, non-activating** persistent staging step. After locking and revalidating the encrypted candidate, pending journal and anonymous rule FDs, it writes content-addressed rule files solely to an independent, private `.ktui-inert-rules-pending-*` directory under the dedicated `inert-rule-bundles` state-directory child. After validating the complete exact file set, it publishes that **private directory** atomically with Linux `RENAME_NOREPLACE` and fsync. It does not overwrite live rules, stage the sing-box executable, write SQLite credentials or activate any historical config. Duplicate complete bundles and abandoned partial scopes fail closed. If interrupted, unfinished scopes need explicit later inspection; no automatic recursive cleanup of unknown contents is attempted. This is not a ready-to-use rules directory or a cross-restart authenticated resource lease. Full transactional restoration remains disabled: `RestoreSupported=false`, `RestoreReady=false`. See [ADR 0114](docs/adr/0114-private-dormant-rule-bundle-atomic-publication.md).

## Read-only authentication of inactive rules after restart (M4, ADR 0115–0116)

The internal read-only `InspectDormantRuleBundles` identifies bounded, private pending and published-looking rule directories after a crash. **Directory names alone are not trusted** and inspection never adopts, deletes or repairs an orphan. `InertRestoreResourceLease.AuthenticateDormantRuleBundle` goes further: after the original O_TMPFILE pins and stage process have closed, a fresh ciphertext lease with an explicitly supplied key and the exact pending v18 journal record reauthenticates the original encrypted archive and SQLite/live CAS, then independently hashes every rule in the precise inactive directory through no-follow descriptors. Missing or extra entries, pending scopes, symlinks, hardlinks, content damage, permissions and concurrent inode/state changes fail closed. A dedicated subprocess/SIGKILL regression confirms the candidate and inactive bytes are rechecked after process death. This is **a momentary read-only observation**, not a durable resource lease or a restore token: `Inactive=true`, `RequiresRevalidation=true`, `RestoreSupported=false`, `RestoreReady=false`. There is still no cleanup, active rule installation, credential migration, SQLite restore, Core activation or user-facing backup/restore command. See [ADR 0115](docs/adr/0115-readonly-dormant-rule-bundle-orphan-audit.md) and [ADR 0116](docs/adr/0116-post-restart-dormant-rule-reauthentication.md).

## Explicit non-destructive retirement of inactive rules (M4, ADR 0117)

After independently authenticating a persisted, **inactive** rule bundle with ADR 0116, the internal-only `QuarantineDormantRuleBundle` operation can explicitly retire it without deleting a single rule. A prior read-only report is treated only as an expected SHA/count fence; the writer independently rechecks the encrypted archive, pending v18 journal, Applied/LKG/selection/declaration/Core CAS and exact rule filenames/contents under both ciphertext and private-stage directory `flock` locks. It then makes **one** Linux `renameat2(RENAME_NOREPLACE)` transition from the published-looking private name to a dedicated `.ktui-inert-rules-retired-v1-<archive-sha>` name. The directory and contents are reverified and fsynced. Unknown, pending, tampered, stale or already-retired scopes fail closed; a crash between rename and parent fsync leaves an ambiguous private retirement that is never automatically adopted or deleted. Subprocess SIGKILL tests and real approved-Core integration verify the operation remains rules-only and non-activating. This is **quarantine, not physical garbage collection**: all rule bytes remain on disk, and existing inventory/publisher operations intentionally refuse the retired scope. No user-facing cleanup, backup restore, active rules/Core publication or SQLite import exists; `RestoreSupported=false`, `RestoreReady=false`. See [ADR 0117](docs/adr/0117-verified-dormant-rule-quarantine.md).

## Cross-restart retired-rule validation and non-deleting reclaim intent (M4, ADR 0118)

An internal `InspectRetiredDormantRuleBundle` now independently reauthenticates a quarantined **rules-only** directory after process death, using a freshly acquired encrypted-candidate flock, the caller-supplied 32-byte key, the exact prepared v18 journal record and live Applied/LKG/selection/declaration/Core CAS. The private scope's canonical rule files are rehashed twice through no-follow descriptors against the authenticated archive inventory. A successful report expires immediately. A separate explicit `BeginRetiredDormantRuleReclaim` rechecks every condition and uses only Linux `RENAME_NOREPLACE` to move the exact private scope to an isolated `.ktui-inert-rules-reclaim-v1-<ciphertext-sha>` name, then verifies unchanged file identities/bytes and fsyncs. A crash between rename and fsync returns **no success receipt** and never triggers automatic readoption or deletion. **No disk space is recovered:** rules remain on disk, `BytesDeleted=false`, the old staging/audit routines refuse reclaiming names, and no unlink, daemon activation, SQLite migration or user-facing backup/cleanup API is implemented. Physical deletion requires a separate durable, resumable per-file protocol with power-loss tests. See [ADR 0118](docs/adr/0118-retired-rule-reauthentication-and-reclaim-intent.md).

## Authenticated crash-resumable one-file cleanup (M4, ADR 0119)

The internal-only reclaim path can now **physically unlink one inactive rule per explicit call** while retaining evidence needed to reauthenticate an interrupted deletion. `PrepareDurableRuleReclaim` first validates the complete original encrypted archive, exact prepared v18 journal/live CAS and 0400 rules; it fsyncs an immutable, HMAC-authenticated plan of exact rule names, bytes, SHA-256 and inode identities, without deleting anything. `UnlinkNextDurableReclaimRule` independently revalidates, fsyncs a separate HMAC deletion intent for exactly one still-present rule, then performs one parent-FD-relative no-follow-verified `unlinkat` and fsyncs the private scope. `InspectDurableRuleReclaim` can reacquire the encrypted archive and key after SIGKILL and accept missing rule bytes **only** for leaves with valid signed, fsynced individual intents; all remaining leaves must still match their original private inode/size/hash. Unknown entries, unjournalled missing bytes and stale live state block the entire operation. The signed plan and intent files remain on disk; authenticated unlinked-byte totals are **not** proof the filesystem has released blocks, and no automatic cleanup, final directory removal, daemon activation, SQLite/credential import or user-facing recovery exists. `RestoreSupported=false`, `RestoreReady=false`. See [ADR 0119](docs/adr/0119-durable-per-file-rule-reclaim.md).

## Immutable terminal rule-reclaim completion (M4, ADR 0120)

After ADR 0119 has durably authorized and unlinked **every** original private, inactive rule, internal `SealCompletedDurableReclaim` independently reauthenticates the complete encrypted candidate, still-prepared journal, live Applied/LKG/selection/declaration/Core CAS, and every signed per-leaf deletion intent. Only when **no** original rules or unknown entries remain can it O_EXCL-create/fsync a separate HMAC-SHA256 `.ktui-reclaim-complete-v1` proof bound to the original plan SHA, archive, inventory, exact journal ID, private directory inode, rule count and original absent byte sum. `InspectSealedDurableReclaim` can verify this terminal state with a new lease after process restart; the earlier per-leaf inspector and unlink operation deliberately refuse the sealed namespace. All original signed plan and per-leaf intents stay on disk and the terminal report is **not** a restore, unlink, whole-directory-delete or GC permit. No automatic cleanup, SQLite restoration, active rule publication, Core execution or user-facing entrypoint is enabled. `RestoreSupported=false`, `RestoreReady=false`. See [ADR 0120](docs/adr/0120-sealed-terminal-reclaim-completion.md).

## Independent, non-deleting terminal audit anchor (M4, ADR 0121)

After ADR 0120 has authenticated every signed deletion intent and permanently sealed the inactive rules-only scope, internal `AttestSealedDurableReclaim` may explicitly add one private HMAC-SHA256 anchor **outside** that scope under the already-owned live state directory. The anchor cryptographically binds the original plan and completion digest, inventory/archive, exact pending journal ID, private scope inode and original absent rule bytes. A second explicit read-only method requires the original ciphertext/key, unchanged live CAS and *all* retained original signed plan/intent/completion files to reauthenticate the anchor after restart, comparing inode identities across two complete scans. Tests cover wrong-key/tamper, duplicate, symlink, stale state and child-process SIGKILL after file fsync but before parent-directory fsync. This is audit evidence only: no final metadata/tombstone removal, credential SQLite restore, Core activation, automatic GC or user-facing backup/restore/cleanup command. Real power-loss T15/T23 and long-term release gates remain open, with `RestoreSupported=false` and `RestoreReady=false`. See [ADR 0121](docs/adr/0121-independent-retained-reclaim-audit.md).

## Bounded copy of complete retired-rule audit proofs (M4, ADR 0122)

After ADR 0120 has signed the terminal state and ADR 0121 has independently attested it, `MirrorSealedReclaimEvidence` can make **one explicit, immutable, 256 KiB-bounded** copy of *all* signed audit proof metadata outside the inactive reclaim directory, under the already-private live SQLite state parent. It embeds exact signed plan/completion/attestation bytes and each authenticated per-rule intent, not rule payloads, Core, credentials or SQLite. An independent cross-restart `InspectMirroredReclaimEvidence` requires the original ciphertext/key, journal and live CAS, and the **entire** still-retained original proof set; inode/contents are rechecked through no-follow descriptors. Failure never triggers repair, deletion or adoption, and duplicate publication is refused. Regression tests include per-proof tampering, live drift, crash interruption, and unchanged active rules with the approved real Core. This is **metadata preservation only**, not transfer of recovery or deletion authority: the original evidence stays intact; no auto GC, final metadata unlink/rmdir, import/restore, Core activation or public backup/cleanup command exists. Both restore flags remain false. See [ADR 0122](docs/adr/0122-bounded-offscope-full-proof-mirror.md).

## Source-scope-independent historical proof inspection (M4, ADR 0123)

Internal `InspectDetachedReclaimMirror(ctx,key)` now reauthenticates an ADR 0122 signed mirror and ADR 0121 external attestation **without opening or requiring the original inactive reclaim directory**. It still requires the original encrypted candidate lease/key, complete SHA/HMAC/inventory and archived SQLite profile/schema verification, exact prepared v18 journal and unchanged live Applied/LKG/selection/declaration/Core CAS. Every nested original plan, completion, external attestation and per-rule signed deletion intent is independently checked against canonical bytes and archive inventory, not trusted solely because the outer mirror HMAC matches. Both external files are checked twice through private O_NOFOLLOW descriptors with inode identity comparison. Tests explicitly move the source directory aside (without deleting it), reacquire the encrypted lease, and confirm historic evidence remains readable while the original source-bound inspector refuses.

This is **historical evidence verification, not current source state validation**: the report explicitly sets `SourceScopeVerified=false`, `RuleAbsenceVerified=false`, `DeletionAuthorized=false`, `RestoreSupported=false`, `RestoreReady=false`, including when the original source scope is missing. No source deletion, operator cleanup, database restore, active Core change or public recovery command is enabled. See [ADR 0123](docs/adr/0123-source-independent-reclaim-mirror-audit.md).

## Read-only reclaim retention review and stable full Race coverage (M4, ADR 0124)

Internal `ReviewTerminalReclaimRetention(ctx,key)` distinguishes two separately authenticated conditions: a complete **historical** HMAC chain outside the inactive reclaim directory and a complete **current source-bound** reinspection of the original plan, deletion intents and sealed completion. Both rely on the original encrypted candidate/key, still-prepared v18 journal and unchanged live Applied/LKG/selection/declaration/Core CAS. If the original source namespace is unavailable, a retained historical audit may still be reported, but `SourceStatus="unverifiable"` and `SourceProofsVerified=false`; it is never interpreted as evidence of safe physical deletion. Even for a fully authenticated original source, `RetentionPolicyApproved=false`, `PowerLossReplayVerified=false`, `PhysicalCleanupAuthorized=false`, `RequiresManualReview=true`, `RestoreSupported=false` and `RestoreReady=false` are mandatory. The inspection never writes/removes metadata or touches active routes. See [ADR 0124](docs/adr/0124-reclaim-retention-review-and-race-stabilization.md).

The previous single-process `go test -race -timeout 30m ./...` occasionally hit its 30-minute budget in expensive backupclosure encryption/SQLite fixtures even on a commit that also had a successful identical CI run. `make test-race` now runs **every** detected top-level backupclosure Test/Fuzz/Example and all other packages under `-race`, split into four deterministic complete slices rather than omitting cases. GitHub Actions runs the four required shards in parallel after ordinary CI, cancels superseded same-branch runs, and still checks format, dependency lock, Vet, full ordinary tests and Build. A green Go Race suite is not proof of real filesystem power-loss durability or long-duration soak stability.

## Bounded retention-footprint census (M4, ADR 0125)

A new **internal-only, read-only** `InspectReclaimEvidenceFootprint(ctx,key)` measures how many ADR 0121 HMAC attestations and ADR 0122 full-proof mirrors exist in the already-private live SQLite state parent, how many filenames share an archive digest, how many are unmatched, and their retained byte totals. A newly acquired prepared ciphertext lease, supplied key, unchanged journal/live CAS and two no-follow inode/content scans are mandatory. Work is bounded to 4,096 parent entries, 256 owned proof files and 40 MiB of retained proof bytes; invalid names, permissions, symlinks, hard links or late same-byte inode swaps refuse. **Paired names do not imply matching or verified HMACs** for other archives. Flags always include `NamesOnly=true`, `CryptographicProofsVerified=false`, `QuotaEnforced=false`, `PhysicalCleanupAuthorized=false`, `RequiresManualReview=true`, `RestoreSupported=false` and `RestoreReady=false`. No evidence is deleted, copied, adopted, expired or automatically cleaned, and no writing quota is claimed. See [ADR 0125](docs/adr/0125-bounded-retained-reclaim-evidence-census.md).

## Cross-process admission guard for retired audit proofs (M4, ADR 0126)

Both explicit internal off-scope proof publishers — `AttestSealedDurableReclaim` and `MirrorSealedReclaimEvidence` — now share a Linux nonblocking advisory `flock` on the **existing, current-UID 0700 live SQLite parent directory**, in addition to their original independently authenticated ciphertext candidate lease. The directory lock spans a bounded full double-scan of all existing owner-private 0400 evidence, prospective **4,096 parent-entry / 256 proof-file / 40 MiB** limits, a fresh pre-openat scan, exclusive creation, file and directory fsync, and two post-publication scans preserving all prior proof inode identities and SHA contents. A busy lock, unexpected preexisting/stale/unsafe proof, exhausted budget or concurrent change fails closed; no repair, lockfile, cleanup, expiration or override is performed. This is an **admission budget for the two cooperating writers**, not a hard filesystem quota for noncooperating processes. Reports remain non-restoring, non-deleting and never authorize physical cleanup. See [ADR 0126](docs/adr/0126-retained-proof-publication-admission.md).

## Non-authorizing manual hold triage of retained proofs (M4, ADR 0127)

Internal `InspectRetainedEvidenceTriage(ctx,key)` reports a **manual hold only** by combining an independently authenticated ADR 0124 *current archive* signature/source review with ADR 0125's bounded **global names-and-bytes-only** proof footprint. It takes a nonblocking shared Linux `flock` on the already-private SQLite state directory, preventing the two cooperating ADR 0126 writers from interleaving during the review, then independently rechecks the signed source/history and the entire bounded footprint. A busy lock, wrong key, canceled context, stale live CAS or inode replacement refuses with no report. The redacted output prioritizes original-source-unverifiable, unpaired names, arithmetic space pressure or missing manual retention policy. It reports exact free directory/file/byte slots and whether a *hypothetical* maximum-size new two-proof pair fits in those numeric ceilings; this is **not a reservation, disk free-space guarantee or permission to publish**. Foreign proofs remain name-only, never authenticated merely through matching suffixes. Every report forces manual hold, no retention-policy approval, no actual power-loss certification, no physical cleanup and no restore readiness. No metadata is written or removed. See [ADR 0127](docs/adr/0127-retained-evidence-manual-hold-triage.md).

ADR 0127 regression hardening: a combined proof review now compares **every original private proof file's inode, SHA and size across the entire operation**, not just equal count/byte reports. The current candidate's two exact external proof files are also bound to their independently authenticated attestation and mirror SHAs. Even a byte-identical replacement of a foreign-looking proof causes refusal with no cleanup or repair. See ADR 0127 for the original CI failure and regression gates.

## Disposable guest SQLite replay subset (M4, ADR 0129; no restore)

The opt-in guest-side `scripts/recovery_lab/guest_reboot_audit.py` adds a **read-only** SQLite subset baseline/after comparison for the ADR 0128 disposable VM lab. Before the intended interruption, it reads a dedicated v18 guest SQLite state with `mode=ro` (WAL-aware), independently checks SQLite integrity/FK, daemon/selection state, Applied/LKG payload SHAs and journal summary, and exclusively fsyncs a private, redacted baseline. After a separately operated guest restart, it requires an operator-pinned baseline SHA and the exact non-authorizing host `virtual_guest_forced_off_observed` witness, then directly re-reads the same guest SQLite and rejects any drift or unreconciled active apply. It never changes live SQLite, stops/starts a VM, fixes state, deletes proofs or activates the Core. All successful outputs still state **no actual guest reboot certification, physical power loss, Core health, encrypted archive authentication, restore or metadata cleanup permission**. See [ADR 0129](docs/adr/0129-disposable-guest-sqlite-replay-subset.md) and the [guest replay runbook](docs/runbooks/t15-t23-guest-sqlite-replay.md).

## T15 real prepared-journal checkpoint in disposable guest (M4, ADR 0130)

A Linux **Go-test-only** guest checkpoint uses the real v18 `storage.Store` to commit one baseline Applied/LKG generation, then fsync a second **prepared but never activated** apply journal. Only when the owned 0700 guest state root and per-nonce witness scope are empty and the non-root operator supplies an exact disposable VM name/UUID/case/nonce acknowledgement does `TestT15DisposableGuestPreparedBoundary` exclusively publish ADR 0128's owner-0600 fsynced `ready-<nonce>.txt` and block for a separately authorized host-side VM interruption. It does not start Core or terminate the guest itself. Ordinary Go CI runs only the bounded temporary SQLite lifecycle test, including explicit safe `RecoverInterrupted` on a throwaway database, and skips the long-lived guest mode. No actual guest stop, power-failure proof, backup recovery or metadata deletion is claimed. See [ADR 0130](docs/adr/0130-t15-real-prepared-journal-guest-lab.md) and [runbook](docs/runbooks/t15-real-prepared-journal-guest.md).

## Real Go v18 ↔ Python guest SQLite replay compatibility (M4, ADR 0131)

Beyond synthetic Python database mocks, Linux Go integration tests now create an actual, disposable v18 `storage.Store`, commit an original Applied/LKG, and independently invoke the real `guest_reboot_audit.py` baseline/after-subset verifier. They require a byte-unchanged real SQLite DB, strict no-power-loss/no-Core/no-restore outputs, refusal after live selection drift and refusal of a real still-active `prepared` apply journal even when a **synthetic, unauthenticated** virtual-stop JSON matches. `RecoverInterrupted` is invoked only on disposable test SQLite and cannot make the original baseline valid again. CI never stops a VM or certifies T15/T23; see [ADR 0131](docs/adr/0131-real-v18-guest-auditor-cross-language-regression.md).

## Prepared-journal after-recovery subset replay (M4, ADR 0132)

The test-only disposable guest Python auditor now writes **v2 pinned baselines** and has an additional `--mode reconcile-verify` for the T15 prepared-journal fixture. This read-only mode compares an original prepared v18 journal to its narrowly expected `interrupted` record after a separately and explicitly invoked `RecoverInterrupted`. It checks unchanged Applied/LKG, candidate generation digests, selected target/route/Core state and journal count, while retaining the ordinary strict `verify` refusal. Python mock tests and the real Go v18 cross-language test exercise valid and corrupted transitions without touching user state. This is **not** an actual VM shutdown, reboot attestation, Core restoration or T15/T23 acceptance. See [ADR 0132](docs/adr/0132-prepared-journal-readonly-reconciliation.md).

## Postactivation manual-hold test boundaries (M4, ADR 0133)

Linux test-only Go v18 fixtures now cover pending apply at `activating`, `verifying`, `rolling_back`, plus terminal `FailRollback`. Real `RecoverInterrupted` on these disposable databases must preserve the confirmed Applied/LKG and candidate config identity, mark an active postactivation attempt interrupted, and **retain** the persistent `RecoveryRequired` flag across idempotent retries and SQLite reopen. The independent Python guest auditor must refuse both exact and prepared-only reconciliation reports even with a synthetic host-stop JSON. No active Core is started, and no public restore, power-loss/reboot verification, archive cleanup or release gate is granted. See [ADR 0133](docs/adr/0133-postactivation-manual-hold.md).

## Complete bounded guest apply-history ledger (M4, ADR 0134)

The **disposable-only** read-only Python audit now captures a **version-3 baseline** with a SHA-256 commitment over *all* retained `apply_history` rows (up to 512; refuse more), not merely the latest archived row. It validates a bounded subset of each terminal archived journal record (IDs, phase/revisions, digests, error length and timestamps) and includes historical fields in the digest without printing raw error text or credentials. The strict and prepared-reconciliation comparisons both pin the ledger unchanged. Python negative fixtures and a real Go v18 multi-generation test reject silent drift of an older archived row even when Applied/LKG and the most recent history record are intact. Prior v2 witnesses cannot be reused. **No real VM stop, power-loss proof, archive HMAC, Core traffic check, restoration or GC permission** is implied. See [ADR 0134](docs/adr/0134-bounded-archived-apply-ledger.md).

## Read-only inert restore journal content audit (M4, ADR 0135)

A pending `inert_restore_preparations` row is **never** a restore permit. The disposable guest auditor now pins the **complete bounded v18 inert journal metadata**, not only the pending count: <=32 records with valid scopes, archive and inventory SHA-256, self-consistent baseline JSON digest, phase/active-slot relation and times produce a private ordered SHA-256 ledger. Guest baseline format changes to **v4**; older version-3 witnesses must not be reused. Negative Python tests and real Go v18 `PrepareInertRestoreRecord`/`AbandonInertRestoreRecord` cross-language checks reject even same-count SHA drift while leaving the confirmed generation unchanged. This provides **no** ciphertext HMAC validation, Core health, VM reboot/power-loss attestation, credential import, retention GC or production restore authority. See [ADR 0135](docs/adr/0135-readonly-inert-restore-journal-ledger.md).

## Canonical Go inert-restore fence audit (M4, ADR 0136)

Disposable guest read-only auditing now requires the **exact Go v18 `InertRestoreFence` JSON schema and compact canonical encoding** for every pending/abandoned inert-restore journal entry, not merely a nonempty JSON object with a matching SHA-256. The guest baseline changes from v4 to **v5** (old pinned witnesses are not silently reused). Synthetic Python tests and real Go v18 temporary-DB tests reject reordered/whitespace-padded or unknown JSON fields and invalid revisions **even after a matching digest is recomputed**, agreeing with the production Go reader's refusal. This creates no restore right, Core activation, VM reboot/power-loss attestation, archive HMAC or metadata cleanup permission. See [ADR 0136](docs/adr/0136-canonical-go-inert-fence-guest-audit.md).

## Retained generation history integrity in read-only guest replay (M4, ADR 0137)

The disposable guest audit now pins a **version-6** baseline containing a SHA-256 ledger of **all retained v18 `generations` rows**, capped at 128. Previously, a historical generation that was not Applied/LKG nor the latest pending attempt could be modified with a matching recomputed SHA without changing the fields checked by the guest snapshot. Python negative tests and real Go v18 multi-generation cross-language tests now refuse this, including malformed optional metadata and timestamp drift, without disclosing config bodies or changing SQLite. Old witness versions are not reused. This still provides **no** Core traffic/VM reboot/power-loss proof, HMAC attestation, file-resource closure, credential import, restore or retention-deletion permission. See [ADR 0137](docs/adr/0137-bounded-retained-generation-ledger.md).

## Bounded declaration revision history in read-only guest replay (M4, ADR 0138)

The disposable Python guest audit now captures a **v7** externally pinned witness with a SHA-256 digest of *every* retained `declaration_revisions` row (max 128), plus an exact immutable parent chain and current revision pointer. Previously, an older routing/DNS source declaration could be altered with a recalculated matching SHA even though Applied/LKG and the current selection had not changed. Synthetic negative tests and a real Go v18 `CommitDeclaration` multi-revision cross-language test cover this gap without exporting declaration JSON or modifying SQLite during the audit. This does **not** authenticate live rule resources, running Core health, archival HMAC, VM reboot/power loss, credentials, restore or GC permission. See [ADR 0138](docs/adr/0138-bounded-declaration-revision-ledger.md).

## Guest v8 retained profile snapshot ledger (M4, ADR 0139)

The disposable read-only SQLite guest auditor now pins the *current and previous* retained profile snapshots and their node JSON payload digests, separate from the v7 routing/DNS declaration ledger. A previous snapshot node replaced together with its stored SHA is detected against the independently pinned witness; evidence is bounded (64 profiles / 128 snapshots / 8,192 nodes / 48 MiB total node JSON), with no plaintext profile data in the report. Real Go v18 `CommitProfileSnapshot` and Python synthetic negative regressions cover this exact subset. This is **not** a new production snapshot limit, live subscription-source/overlay audit, actual VM reboot/power-loss verification, archival HMAC, Core health proof, restoration, cleanup or release acceptance. See [ADR 0139](docs/adr/0139-guest-profile-snapshot-ledger.md).

## Guest v9 persisted node user-overlays (M4, ADR 0140)

The disposable read-only guest audit now separately pins **all** persisted node disabled/favorite/alias/sort-rank overrides, including overlays deliberately retained for removed/dormant nodes. Earlier v8 Profile snapshot digests alone did not cover these user settings. The new v9 private witness contains only row counts and an ordered SHA-256; the guest refuses an unchanged-CAS-revision overlay alteration, invalid Go-shaped values and over 2,048 total overlay rows. This is a deliberately narrower **guest test limit**, not a new production quota. Real Go v18 CAS/snapshot persistence and Python negative tests cover the gap. Source URLs/update state remain outside the audited subset. No real VM restart, Core proof, HMAC, restore or GC authorization is claimed. See [ADR 0140](docs/adr/0140-guest-profile-overlay-ledger.md).

## Guest v10 profile source/lease/usage evidence (M4, ADR 0141)

The disposable v18 SQLite read-only guest audit now pins every retained `profile_sources` field, independently from node snapshots and user overlays: subscription URL/path, fetch/filter/schedule, HTTP revision/ETag, failure/retry data, usage counters/expiry, and in-flight update leases. A source need not have a snapshot yet. A bounded, SHA-256-only private witness detects changed URLs or usage without source CAS advancement, including independently persisted lease recovery; it does **not** export tokens/URLs or authenticate remote data. The 64-source cap is **guest-only**. Python negative tests and real Go Store v18 cross-language tests cover this subset. Witness v10 supersedes v9 only for new experiments; no actual VM reboot, Core health, archive HMAC, restore or deletion rights are claimed. See [ADR 0141](docs/adr/0141-guest-profile-source-ledger.md).

## Guest v11 host stop-intent continuity (M4 ADR 0142, lab-only)

The disposable read-only guest auditor now pins the exact phase-ready marker **before** stop, then requires both original owner-private host `intent` **and** `observation` receipts (case/nonce/domain/UUID, marker SHA, strict false capability flags, UTC ordering) during either SQLite verification mode. An incomplete/mismatched host stop chain can no longer pass merely because the SQLite v18 subset is intact. Synthetic tests exercise the **real host writer under mock libvirt** and Go v18/Python cross-language refusal; **no VM is actually stopped, rebooted or authenticated**. Baseline witness v11 is incompatible with v10, and the product SQLite version remains 18. All Core/restore/deletion flags remain false; see [ADR 0142](docs/adr/0142-host-stop-chain-guest-evidence.md).

## Host post-start guest witness (M4, ADR 0143)

A separate **non-destructive** ordinary-user host tool, `scripts/recovery_lab/vm_postboot_observe.py`, now observes the same disposable libvirt `qemu:///session` VM as `running` **after an operator manually restarts it**. It never starts/stops a VM. A private O_EXCL poststart receipt is written only with exact one-time acknowledgement and original externally pinned v12 guest baseline SHA, then the read-only guest Python checker requires the receipt's raw hashes of phase marker, baseline, original stop intent and observed shutoff. Tests include fake libvirt and real Go v18 SQLite; they are **not actual virtual or electrical power-interruption tests**. All Core, archive/credential restoration and metadata-delete authority remain false, T15/T23/T25 OPEN. See [ADR 0143](docs/adr/0143-host-poststart-observation-ledger.md).

## Guest Linux kernel boot-identity replay evidence (M4 ADR 0144)

The optional `scripts/recovery_lab/guest_kernel_boot_epoch.py` captures the *actual Linux procfs boot ID* into a private, independently SHA-pinned pre-stop record, then requires a **different** procfs boot ID when validating the complete pre-cut marker, host intent/stop and poststart evidence after the operator's manual VM restart. Unlike the host's libvirt `running` observation, this catches the **same-kernel/no-restart** case; unlike real hypervisor or hardware attestation it does not prove a genuine VM or physical power interruption. Python negative regressions and a real Go v18 SQLite cross-language test insist that the CI kernel's unchanged ID never passes. No guest v12 baseline format or production SQLite v18 changes; no Core, restoration or cleanup rights. [ADR 0144](docs/adr/0144-guest-kernel-boot-epoch.md).

## CN offline T24 provenance-only audit hardening (ADR 0145)

The dedicated Linux CN resource audit reads the pinned Karing 28-group plus region-append **68 logical** references as a bounded, descriptor-relative, no-follow source tree: 67 file candidates, one documented missing `geoip:bing`. It now refuses symlink/hardlink/special/oversized/changed files and checks a per-file **8 MiB** and aggregate **64 MiB** audit budget; the PR-triggered provenance workflow checks the pinned upstream commit/clean working tree and uploads only JSON metadata. This is **NOT** a licensed, verified, distributable offline bundle: `distribution_ready=false` and `blocked_unresolved_upstream_data_licenses` are deliberate blockers. Normal proxy/Core/SQLite behavior is unchanged. See [ADR 0145](docs/adr/0145-cn-resource-audit-nofollow.md).

## Native no-network bootstrap preflight (M5 ADR 0146; T24 still OPEN)

The `core-provenance` workflow now runs on relevant PRs for **both native amd64 and arm64**. After preparing and verifying the approved Core and compiling the management CLI, it executes `scripts/offline_lab/t24_airgap_bootstrap.py` as an unprivileged process in a Docker **`--network none`** container with no effective Linux capabilities, read-only image/binaries, and private ephemeral XDG paths. The test checks Core **version/config syntax only**, starts/stops the real Daemon twice, reads private SQLite state and the Unix socket, and insists that CN bundle distribution and Core activation remain disabled. The test never downloads rules or accesses a network **inside** the container. CI still downloads/builds dependencies and an unpinned OCI image **before** isolation. This is a **partial T24 cold management-plane bootstrap**, not full offline installation or live Core/DNS/CN rule validation; no bundled CN license approval, no release authorization. See [ADR 0146](docs/adr/0146-native-airgap-bootstrap-preflight.md).

## Native offline loopback Core test (M5 ADR 0147, still T24 partial)

The two native Linux architecture CI jobs now use a **digest-pinned** test OCI image and run an additional non-root `docker --network none` container. The SHA-verified standalone Core really starts and carries SOCKS5 traffic from each of three local-only Mixed ports to an in-container 127.0.0.1 TCP echo server; its local Clash API rejects unauthenticated requests and exits cleanly on SIGTERM. This checks **only localhost data flow with no external network**, not CN SRS rules, remote proxies, DNS, licensed offline packaging or production Daemon integration. See [ADR 0147](docs/adr/0147-native-airgap-loopback-core.md).
