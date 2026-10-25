# Compatibility matrix

This file records implemented compatibility, not intended future support. A format/protocol is only marked supported when the importer preserves every field required by the implemented domain/compiler path and tests cover the resulting behavior.

Baselines:

- Karing application source: `KaringX/karing@9d28b22fbbcca5818d147629aae151d49d4dcb7b`
- approved runtime core: `KaringX/sing-box@beddeababcc71dfb0c78124598b13341c06c69fb`
- product routing model: Custom -> GeoSite -> GeoIP -> ACL -> FINAL
- subscription/ISP routing layers: intentionally excluded

## Native sing-box profile import

Current implementation: `internal/importer/singbox.AnalyzeBasicProfile`.

| Source item | Status | Behavior |
| --- | --- | --- |
| HTTP outbound: `tag` | Supported | Used as profile-local source key; project NodeID remains separate and stable |
| HTTP: `server`, `server_port` | Supported | Validated by the domain node model |
| HTTP: `username`, `password` | Supported | Preserved in the accepted outbound payload and materialized domain node |
| HTTP TLS / detour / dial extensions | Blocked | Import receives an error-level compatibility diagnostic; no snapshot commit |
| SOCKS: `tag` | Supported | Used as profile-local source key |
| SOCKS: `server`, `server_port` | Supported | Validated by the domain node model |
| SOCKS: `version` | Supported | `4`, `4a`, `5`; omitted value defaults to `5` |
| SOCKS: `username`, `password` | Supported | Domain restrictions are enforced |
| SOCKS: `network` | Supported | `tcp`, `udp`; omitted value materializes as both where valid |
| SOCKS `udp_over_tcp`, detour, dial extensions | Blocked | No silent field loss |
| `direct`, `block`, `dns` outbounds | Ignored as non-node plumbing | Reported; not imported as proxy nodes |
| selector / urltest source outbounds | Blocked | Not silently converted into project SelectionGroups |
| VMess basic subset | Supported | uuid/security/alter_id/global_padding/authenticated_length/network/packet_encoding plus verified basic TLS; multiplex, transport and other dial extensions block import |
| VLESS basic subset | Supported | uuid/network/packet_encoding plus no-op encryption and verified basic TLS; packet_encoding omission vs explicit empty is preserved; flow, custom encryption, multiplex, transport and dial extensions block import |
| Trojan basic subset | Supported | password/network plus verified basic TLS; multiplex, transport and other dial extensions block import |
| Shadowsocks: `method`, `password`, optional plugin/plugin_opts, network | Supported basic subset | Complete supported fields are preserved; unsupported UDP-over-TCP/multiplex/dial extensions still block import |
| Hysteria / Hysteria2 | Not yet supported | Blocks complete automatic import |
| TUIC | Not yet supported | Blocks complete automatic import |
| source `route` | Intentionally ignored | Reported as `ignored_by_product_policy`; cannot create runtime RuleGroups or FINAL |
| source `dns` | Intentionally ignored for profile import | Project DNS is separately declared; source policy is reported |
| TUN / TPROXY / redirect inbound | Forbidden | Entire import rejected by proxy-only safety validation |
| `auto_route`, `auto_redirect`, enabled `set_system_proxy` | Forbidden | Entire import rejected |

Accepted node payloads are stored immutably in the profile snapshot with their SHA-256. The current and immediately previous successful profile snapshots are retained; older profile snapshots are pruned.

## URI-list profile conversion

Current implementation: `internal/importer/urilist.AnalyzeBasicProfile`.

| Source item | Status | Behavior |
| --- | --- | --- |
| decoded newline-delimited URI list | Supported source format | Blank lines and `#` comment lines are ignored; source bytes remain hash-bound to the snapshot |
| Shadowsocks SIP002 `ss://BASE64(method:password)@host:port` | Supported basic subset | Converts to the already validated native Shadowsocks node model |
| SIP002 `plugin` query | Supported | First semicolon separates plugin name from `plugin_opts`; unknown or repeated query keys block import |
| URI fragment display name | Supported metadata | Excluded from semantic SourceKey, so renaming the fragment preserves stable NodeID |
| duplicate semantic URI | Blocked | Prevents two display names from aliasing one stable source identity |
| legacy base64-whole Shadowsocks URI | Not yet supported | Blocks complete update rather than guessing legacy parsing |
| VMess/VLESS/Trojan/Hysteria/TUIC share URI | Not yet supported | Blocks complete update until URI transport/TLS defaults have explicit verified mappings |
| oversized URI line / more than 10,000 nodes | Blocked | Parser is bounded; one line is limited to 16 KiB |

The URI-list converter emits canonical sing-box basic-node payloads and then reuses the same strict sing-box importer/domain validation. Converted profiles therefore do not create a second runtime interpretation path.

## Runtime node compiler

The current declaration/runtime compiler can materialize:

| Node type | Runtime status | Important boundary |
| --- | --- | --- |
| HTTP CONNECT | Implemented | Plain HTTP proxy node only; TCP |
| SOCKS4 | Implemented | TCP only |
| SOCKS4a | Implemented | TCP only |
| SOCKS5 | Implemented | TCP/UDP/both as represented by the domain model |
| Shadowsocks | Implemented basic subset | method/password/plugin/plugin_opts/network; no UDP-over-TCP, multiplex or detour field loss |
| VMess | Implemented basic subset | uuid/security/alter_id/global_padding/authenticated_length/network/packet_encoding plus basic TLS; no multiplex, V2Ray transport or detour field loss |
| VLESS | Implemented basic subset | uuid/network, lossless packet_encoding presence and basic TLS; empty/none encryption only; flow/custom encryption/multiplex/transport/detour remain blocked |
| Trojan | Implemented basic subset | password/network plus basic TLS; multiplex/transport/detour and other dial extensions remain blocked |
| Domain-valued node server | Implemented with explicit Outbound DNS | Fails closed without configured node/outbound resolver |
| Basic outbound TLS | Implemented for VMess/VLESS/Trojan | `enabled:true`, `server_name`, `insecure`, `disable_sni`; omitted TLS remains omitted; explicit disabled TLS and unmodelled TLS fields block import |
| Reality/uTLS/ECH/certificates/advanced TLS, transport/Mux | Not yet implemented | Must not be dropped by importers |
| Detour/pre-proxy chain | P1 / not yet implemented | Unsupported imported detour must block application |

## Routing compatibility

| Capability | Status |
| --- | --- |
| Custom -> GeoSite -> GeoIP -> ACL -> FINAL ordering | Implemented |
| independent Custom/GeoSite/GeoIP/ACL switches | Implemented |
| typed DIRECT/BLOCK/CurrentSelected/Global URLTest/Custom URLTest/Specific Node targets | Implemented |
| exact CN 28-group preset snapshot | Implemented as vendored semantic snapshot |
| CN full offline production closure | Blocked on redistribution/license/resource closure |
| region GeoSite/GeoIP auto append | Implemented |
| subscription routing layer | Intentionally not implemented |
| ISP routing layer | Intentionally not implemented |
| imported MATCH/FINAL/rule-provider routing | Intentionally stripped/reported |
| CurrentSelected durable live update | Implemented and real-core tested |
| explicit custom URLTest node members | Implemented |
| Karing saved custom URLTest `regexs` runtime semantics | Pending evidence | Public UI proves candidate-search behavior, but the runtime builder needed to prove saved dynamic expansion is absent from the fixed public snapshot |

## DNS compatibility

Implemented and observed on the approved core:

- bootstrap resolver chains;
- outbound/node DNS;
- Direct DNS;
- Proxy DNS through CurrentSelected;
- Group DNS for pre-resolution-safe groups;
- global fallback DNS;
- fail-closed default DNS when no fallback is configured.

Still separate work:

- FakeIP;
- system DNS takeover;
- ECS;
- static hosts parity;
- additional encrypted DNS transports;
- address-family policy;
- remote-proxy hostname-resolution mode;
- classification DNS for rules that require unresolved destination IP state.

## Update semantics

Implemented profile foundation:

- stable profile-local source-key -> NodeID reconciliation;
- no same-name heuristic rebinding;
- immutable current/previous source snapshots;
- exact accepted node payload SHA-256;
- default refusal of empty source updates;
- failed/unsupported imports do not advance current snapshot;
- exact retained snapshot ID can be materialized into a declaration-v1 candidate;
- profile node replacement reports added/removed/retained NodeIDs and fails closed when a removed node is still referenced;
- successful snapshot-to-declaration updates use declaration revision CAS and bind runtime-relevant node overlay state into `profile-snapshot/<id>/overlay/<sha256>` provenance;
- per-node Disabled/Favorite/Alias/SortRank overlays are persisted by stable (ProfileID, NodeID) with independent CAS;
- Disabled and SortRank overlays are applied deterministically at snapshot-to-declaration materialization; Favorite/Alias remain non-runtime user metadata;
- dormant overlay rows survive temporary source-node removal so stable NodeID reappearance restores user state; retained rows are bounded per profile.

Implemented source/update-state foundation:

- revisioned ProfileSource configuration with CAS;
- HTTP/HTTPS URL and absolute local-file source modelling;
- native sing-box and strict decoded URI-list source formats;
- Direct / CurrentSelected / Specific Node fetch-policy modelling;
- persisted ETag, Last-Modified, Retry-After and consecutive-failure metadata;
- bounded Subscription-Userinfo upload/download/total/expiry metadata with last-known-good preservation;
- independent metadata observation timestamp so stale HEAD results cannot overwrite newer usage/error state;
- metadata-only HEAD refresh storage uses source-revision CAS and refuses to commit while a full profile update lease is active;
- request-start timestamps prevent a late HEAD response from overwriting newer full-refresh usage/error metadata;
- one crash-safe active update lease per profile;
- daemon-start recovery of interrupted update leases;
- source configuration cannot change while its worker lease is active;
- source identity edits clear stale validators/backoff/usage metadata while retaining the last accepted snapshot.
- persisted Karing-shaped node filter state (all/include/exclude, keyword-or-regex, match-attribute) with revision/CAS; execution remains disabled pending verified vpn-service semantics.

Implemented refresh/scheduling foundation:

- bounded HTTP/HTTPS fetch with explicit Direct/Selected paths and no environment-proxy inheritance;
- ETag/Last-Modified conditional requests and 304 handling;
- HTTP Retry-After capture without retaining remote error bodies;
- bounded Linux local-file reads with final-component nofollow and regular-file checks;
- refresh coordinator that acquires the source revision lease before reading the source specification;
- atomic accepted snapshot + update-success commit;
- Karing-confirmed remote update interval model: disabled/0, minimum 5 minutes, default constant 12 hours, maximum 365 days;
- persisted update interval and stable profile-source listing;
- staggered overdue startup planning, bounded exponential failure backoff and stable per-profile jitter;
- global scheduled-refresh concurrency budget plus same-profile non-reentry;
- scheduler cancellation waits for active workers;
- dedicated GET + bounded HEAD-refresh profile metadata API for traffic/quota/expiry display;
- versioned profile source management API: list/get, strict revision-CAS upsert and explicit full refresh for sing-box/decoded URI-list sources;
- explicit manual full refresh returns node count, accepted snapshot ID and policy/compatibility diagnostics without automatically replacing the applied configuration;
- metadata HEAD and manual full-refresh API share a four-operation budget and per-profile non-reentry; HEAD requests retain a five-second upstream timeout ceiling; manual full refresh has a 60-second request deadline;
- metadata-only network failures do not mutate node snapshots or full-refresh failure/backoff health;
- internal client methods consume the metadata API so future TUI code does not read SQLite directly.

Still not implemented:

- additional URI-list schemes beyond Shadowsocks SIP002, base64-wrapped V2Ray subscriptions and Clash/YAML conversion;
- Specific Node network fetch execution;
- automatic snapshot -> declaration -> compile/apply policy after a refresh;
- source node filter execution semantics (Karing UI state is persisted, but exact vpn-service matching behavior is not yet verified);
- provider materialization.

## CLI integration

The local `profiles` CLI currently supports credential-safe profile summaries (`list`), source-order node pages (`nodes`), and explicit revisioned full node overlay replacement (`replace-overlay`). The CLI does not infer Karing's unknown filtering semantics or silently apply source route content. The snapshot-to-declaration and runtime apply transaction remain distinct and require explicit future orchestration.

## Profile source CLI (M3)

`profiles put <id> --expected-revision=N --stdin` sends a strict, bounded JSON source specification to the existing source CAS API; successful output is a credential-safe summary. `profiles refresh <id> --expected-revision=N` invokes the existing bounded manual update lease; it requires an explicit `--allow-empty` to accept an empty result. Refresh output contains only normalized diagnostic levels/codes, not untrusted message text or raw upstream configuration. Neither operation accepts subscription route/rule-provider/ISP routing as runtime route data or automatically updates the applied declaration.

## Profile snapshot proposal preview

`POST /v1/profiles/{profile_id}/declaration/preview` provides a bounded, credential-free V1 declaration proposal summary for an exact current accepted snapshot. It supports only the implemented canonical basic-node subsets, preserves stable identities and runtime overlays, and refuses stale references and required disabled nodes. This is not proof that a candidate will pass the pinned core checker: it is not committed or applied, and subscription/ISP routing is still excluded.

The same preview is accessible through `karing-tui profiles preview <id> --snapshot-id=N --expected-declaration-revision=N`. Both revision inputs are required and validated before making an RPC, and daemon errors are summarized without echoing potentially secret-bearing untrusted strings.

## Explicit profile declaration staging (M3/M4)

The candidate returned by `profiles preview` can be staged as a **new immutable declaration revision** with `profiles stage <id> --snapshot-id=N --expected-source-revision=N --expected-declaration-revision=N --candidate-sha256=HASH --runtime-overlay-sha256=HASH --confirm`. Every flag is mandatory; hashes must be canonical 64-character lowercase SHA-256 hex strings. The daemon verifies the exact accepted snapshot, preview-acknowledged source revision, enabled source state and runtime overlay revisions, re-materializes the candidate and checks both user-acknowledged hashes, then uses a single SQLite guarded CAS transaction. Missing/removed selected nodes, stale snapshots, changed runtime overlays and concurrent competing stages are rejected.

Staging deliberately returns `core_validated=false` and `applied=false`: it **does not run the pinned core checker, activate a generation or restart core**. The explicit compile/apply API remains independently guarded, and neither stage nor preview imports subscription/ISP routing.

## M4 first Bubble Tea TUI slice

`karing-tui tui` is a read-only Bubble Tea v1.3.10 client using daemon Unix Socket APIs; it never reads the SQLite store or launches/stops core. Its Dashboard distinguishes daemon/core status, configuration/declaration revisions, applied/LKG generation and recovery requirement. Profiles lists safe source IDs, type, enabled state and failure counters, while Nodes displays stable IDs and user aliases without disclosing source URLs, source keys, proxy credentials or raw error messages.

The view implements terminal size handling, Chinese width-aware sanitization, bounded lists and node pages, request timeouts, cancellation on UI exit, explicit refresh (no implicit polling), and stale-response suppression by request generation. All terminal control/format and bidi controls are filtered before rendering untrusted fields. `q`/Ctrl-C only exits the TUI; there is no implicit configuration mutation or core lifecycle action.

This is a bounded **read-only** milestone. Interactive node choice, routing/DNS editing, connection/log inspection, backup/rollback, complete filters and protocol coverage remain outstanding. Subscription/ISP routing remains excluded.

## M4 compiler-previewed Routing group and DNS binding stage

On the Routing page (`7`), an operator may select an existing editable group from a **complete applied-generation declaration** and propose one change: `e` toggles enabled; `t` chooses a typed outbound target; `g` chooses/clears an existing group-role DNS binding. Target candidates are the four built-in types and stable specific-node/custom URLTest references **already present in the same complete applied snapshot**; they are not a full node picker. DNS profile choices are available only when the resolver list is untruncated. FINAL and derived region-auto entries remain read-only. A partially loaded or previously staged declaration cannot authorize edits.

The terminal never writes node or rule configuration directly: a new edit context must match current declaration/config/applied-generation identity, the daemon strictly compiles a proposed one-field diff, and the TUI checks the echoed request, before/after values, CN override provenance, compiler result and both SHA-256 digests. A second deliberate `y` stages only a new immutable declaration revision through CAS; core validation, activation and rollback UX remain separate. Ambiguous outcomes do not automatically retry. The approved KaringX/sing-box runtime, five routing layers and subscription/ISP-route exclusion remain unchanged. See ADR 0080 and ADR 0081.

## M4 checked current-declaration apply (CLI and confirmed Dashboard TUI)

`config apply-preview` performs a read-only strict compile of the *current unapplied declaration head* under the daemon operation gate and provides only a bounded receipt; it does **not** claim core validation. `config apply --receipt=PRIVATE_FILE --confirm` requires a private user-owned regular file, immutable declaration and native config SHA-256, config revision/applied generation and CurrentSelected revision; the daemon revalidates and recompiles inside one gate before its existing transactional check/activate/verify/commit sequence. CLI readback checks the persisted generation/revision. A mismatch, missing provenance, stale head or already-applied declaration fails closed. No native core JSON, matcher literals or DNS addresses are sent through these endpoints.

On activation or verification failure the managed apply coordinator handles rollback to the preceding generation and recovery-required state if rollback is unsuccessful. A lost HTTP response is **not** proof of either success or failure; no automatic apply retry is permitted. Historical rollback selection, multi-group atomic editing, T10 live DNS-path equivalence, complete CN/offline resources and long-run reliability gates remain unresolved.


### M4 Dashboard operator confirmation

Page `1` offers `a` for the same **current-head compiler-only** checked apply preview; the operator must explicitly press `y` after viewing the revision, both SHA summaries, applied generation, selection revision and core interruption warning. `Esc` cancels. The modal is disabled below 64×16 terminal columns/rows and discarded after a shrink; it never auto-confirms. While a confirmed apply is in-flight, keyboard navigation/refresh cannot dispatch a second mutation. `q` only terminates the TUI; an already accepted daemon apply can still finish. The TUI validates the receipt against a fresh Dashboard identity, then reuses the exact CLI's guarded endpoint and strictly compares acknowledgement and durable status readback. Unknown outcomes are reported as uncertain and never retried. No manually selectable historical-generation recovery or automatic TUI rollback button is exposed. ADR 0083 documents the scope.


## M4 confirmed generation history and immutable-resource audit

`config recovery-audit` is a **read-only** bounded privacy-safe historical inventory. The daemon merges up to 12 unique successfully committed generation records from live `apply_journal` and compact `apply_history`; prepared, interrupted, rolled-back or failed candidates are not offered. Retention-pruned generations remain visible as historical records with `payload_retained=false`, never as recovery-ready targets. Stored payload integrity requires SHA-256 verification of config/manifest/source-map, matching manifest schema and declaration identity, retained immutable declaration JSON integrity, and declared model parsing. External rule-set paths must resolve to the configured private content-addressed store with source/binary format and SHA-256 verified through the existing no-symlink/private-owner verifier. Neither manifest paths nor native JSON or secrets leave the daemon. A concurrent config-generation or declaration-head drift results in a read conflict.

`stored_integrity_verified_only` never implies live core/check/detour parity. Every record reports `restore_ready=false` and the API reports `restore_supported=false`; no write, automatic retry, mutation confirmation or historical rollback endpoint has been added. Next gate: historical selector/role/resource provenance, immutable restore CAS, real managed-core preflight, transactional rollback-of-rollback and failure-injection coverage. ADR 0084.

## M4 TUI historical inventory (read-only)

TUI page `9` adds on-demand, bounded, cancellable display of the existing committed-generation recovery audit. CLI and TUI share one strict API validator (including `restore_supported=false`, per-generation `restore_ready=false`, status/preflight enum and consistency checks). Only allowlisted metadata is projected into terminal strings; no historical check, core activation or restoration is offered. This does not change M4 manual-restore readiness or any M5 stability gate (ADR 0093).

## M4 internal consistent-database snapshot prerequisite

The storage layer can now stage a private WAL-consistent SQLite copy with a bounded `VACUUM INTO` operation, offline read-only integrity validation and SHA-256, explicit temporary file ownership and guarded cleanup (ADR 0094). The method remains internal-only: it does not export or restore sensitive profile credentials, and does not include the immutable external rule-set/core resource closure. No backup/restore UI or public API is implemented, and `restore_supported=false` remains unchanged. Future portable backups require verified consistent resource inclusion, safe archive/encryption, crash recovery and transactional restore with rollback.

## M4 cross-process safe SQLite snapshot orphan recovery

Internal snapshot staging now coordinates scoped `flock` leases with a bounded private-parent reclamation scan in a distinct `.sqlite-snapshot-v2-*` scope namespace (ADR 0095). Stale empty or one-file interrupted SQLite scopes can be reclaimed opportunistically without touching active snapshots; unexpected entries or replaced/unsafe paths are refused. This closes the **known orphan-scope cleanup gap only for future internal snapshot attempts**, not a periodic startup cleaner or portable backup. Product backups still require resource closure, manifest, encryption and safe restore; no API/CLI/TUI restore is enabled.

## M4 database-consistent ephemeral rule-resource closure

ADR 0096 introduces an internal-only, 90-second-bounded snapshot inventory: it reads all retained generation provenance from a single immutable SQLite snapshot, verifies native local rule paths, hashes and declaration bindings, then temporarily pins/copies the deduplicated external rule files. The canonical in-memory inventory contains only relative rule digests, generation digest references and the SQLite copy hash. Unknown legacy generations and unsafe resource states fail closed. This is **not a durable resource lease** and does not package the pinned core binary or grant manual restore; backup export and restore remain unsupported.

## M4 approved-core ephemeral binary closure (non-executable)

ADR 0097 binds the approved Linux core's locked version/architecture/commit/SHA-256 into an **internal v2** database/rule inventory. The source executable remains inode-pinned, and an independent non-executable 0400 copy is checked within the existing bounded, flock-held rule snapshot scope; the orphan scavenger recognizes this single new file type and rejects unknown entries. `BuildWithApprovedCore` admits only lock-approved hashes; v1 `Build` still omits the core explicitly. The real approved core is exercised by managed-core-integration. No durable archive, recovery authorization, historical restore, CLI/API/TUI backup or release approval follows from this evidence.

## M4 strict inert snapshot inventory parsing (no restoration)

ADR 0098 adds a canonical, bounded SHA-256 inventory parser for the internal v1/v2 SQLite/rule/core closure. Unknown or duplicate JSON keys, extra whitespace, unsupported manifest versions, out-of-order/duplicate generation and rule records, traversal paths, resource-size overruns, unlocked core identifiers, and any `restore_ready=true` claim are refused. The already-held closure's verification additionally binds the in-memory inventory to the exact database SHA/size and pinned rule descriptors. This is only an offline metadata validation prerequisite: a caller-supplied digest is **not a signature**, and neither file provenance nor a durable restore lease is inferred. Export and restore surfaces remain disabled.

## M4 internal authenticated encrypted snapshot archive prototype

ADR 0099 adds a private, **internal-only** sealed archive writer and offline read-only verifier for the pinned WAL-consistent database and independent rule/core copies. The bounded binary envelope uses random-IV AES-CTR encryption with a separately derived HMAC-SHA-256 Encrypt-then-MAC tag; no plaintext resource is written to the archive directory. The verifier checks the whole MAC, canonical inventory and every decrypted record SHA-256 without extraction or activation. Private no-overwrite atomic publication and basic free-space checks are enforced; failed publication is an uncertain outcome. The symmetric key must be supplied by an internal caller and is never embedded in output; key management, stable portable format approval, export/restore, archived-scope scavenging and rollback safety are **not implemented**. The v1 archive is explicitly incomplete (no core); v2 is still `restore_ready=false` and not supported for restore.

## M4 sealed archive crash cleanup and retention refusal (internal only)

ADR 0100 introduces a new, lease-aware `.ktui-sealed-v2-*` ciphertext staging namespace, parent/file Linux `flock` coordination and bounded orphan cleanup. An active writer is never reclaimed; a SIGKILL-abandoned unlocked v2 temporary may be removed after strict UID/mode/inode/link/budget checks. Legacy unleased temporary names, unknown files and ambiguous partially published hard links fail closed. Published `.ktbackup` files are NEVER automatically deleted: a read-only metadata inventory imposes a maximum of eight retained archives and 32 temporary candidates, refusing more writes at capacity. No periodic cleaner, user-facing backup manager, key lifecycle, migration or restore permit is implied.

Concurrent encrypted writers reserve one of the eight retention slots and worst-case bytes for each active temporary file under the directory lock; they cannot both use the final available slot. The reservation is released only after safe abandoned-v2-file reclamation.

## M4 authenticated inert archive preflight (no extraction or activation)

ADR 0101 adds internal-only `PreflightInertArchive`. It returns an allowlisted, non-secret compatibility/digest-difference summary only after a complete HMAC-verified, record-hashed archive pass and an independent full-ciphertext SHA-256 replay that binds the inspected inventory bytes to the verified receipt. The optional current baseline is a still-verified temporary closure, not an unguarded read of the mutable live database. Digests compare content, never reused row IDs. A v1 archive reports a missing approved core; v2 core metadata must match a pinned architecture-specific core identity, and a different host architecture is flagged. **`TargetMetadataCompatible` is not a restore permission.** The backup SQLite database has not been independently opened for schema/foreign-key/journal verification, and restore/import/application remain unsupported, with `RestoreSupported=false` and `RestoreReady=false`. No user API, plaintext extraction or active proxy operation is involved.

## M4 independently verified SQLite logic inside authenticated archives

ADR 0102 extends the internal `PreflightInertArchive` with a third whole-ciphertext SHA-256 pass that materializes **only the authenticated SQLite record in bounded memory**, never as a plaintext file. The existing pinned pure-Go SQLite driver deserializes it into a separate single-connection in-memory database. Full `integrity_check`, foreign-key consistency, exact 17 migration versions, bounded declaration history, singleton metadata, compiler-owned native generation/manifests and original local resource references are checked against the already MAC-authenticated archive inventory. On success, the nonsecret report has `SQLiteLogicalVerified=true` and `DeclarationCount`, replacing the earlier incomplete SQLite-logical-check blocker. Databases over **64 MiB** are refused without attempting to allocate for verification; this does not change the larger encrypted snapshot/archive transport capacity. Even a fully verified v2 archive is **not importable or restorable**: no durable resource lease, schema migration, complete profile semantic inspection, restore transaction or rollback-of-rollback is enabled.

## M4 exact SQLite schema and bounded profile-state audit

ADR 0103 extends the authenticated archive's in-memory SQLite preflight. A freshly migrated **in-memory reference schema using the real migration code** is compared against the archive's entire `sqlite_schema` (all table/index/trigger SQL, bounded by 128 objects/1 MiB). It also verifies bounded profile snapshots, ordered node payload hashes/JSON, source specifications and subscription metadata, profile-owned current/previous snapshot pointers, node overlays and selection intent. Report fields are only a schema-verified boolean and aggregate counts. A mutated and reauthenticated archive still fails if it contains plausible migration numbers but nonmatching DDL or invalid domain rows. The existing 64 MiB memory audit cap and **no restore, activation, plaintext disk extraction, or credential disclosure** restrictions are unchanged.

## M4 encrypted inert restore candidates, process lease and re-adoption

ADR 0104 introduces strictly internal, ciphertext-only persistent candidate scopes. After fully authenticating/inspecting an existing `.ktbackup`, the code copies the exact encrypted bytes to a single UID-owned 0600 `candidate.ktbackup` in a separate exclusive-flock-guarded 0700 `.ktui-restore-v1-*` scope, then reauthenticates the copied archive. A dedicated parent directory lock and eight-scope limit prevent simultaneous duplicate slot use. `Close`/SIGKILL only release the live Linux lock; encrypted bytes survive, and a future owner must reacquire the lock and **resupply the key and re-run complete HMAC/resource/SQLite/domain preflight**. The explicit internal `Discard` refuses unknown files and does not recursively delete. No plaintext import, runtime activation, backup key storage, automatic orphan deletion, T15/T23 restoration, or privilege escalation is possible through this slice. In particular, releasing a process lock is not a durable activation lease and `RestoreReady=false` / `RestoreSupported=false` remain mandatory.

## M4 read-only transactional restore fence and injected dry-run checks

ADR 0105 adds `storage.ReadInertRestoreFence` and `backupclosure.InspectInertRestoreDryRun`, an **internal-only optimistic inspection** that binds the live committed config/apply/LKG, declaration, selected target, routing/core desired state in one SQLite read transaction, rehashes committed immutable blobs, authenticates the exclusively held encrypted candidate twice, then compares a fresh SQLite read fence against the first. The result contains only IDs, revisions and SHA-256 digests, with explicit `RestoreSupported=false` / `RestoreReady=false`. Fault-injection tests change live selection/declarations, tamper ciphertext after the first pass, cancel, and force recovery/active-apply guards. No `prepared` record, runtime core action, plaintext file or restore entrypoint is created. Read-only fence equality is **not an atomic write CAS**; writes after inspection remain possible, so future restoration must provide a fresh transaction-local CAS, daemon operation gate and tested dual rollback.

## M4 rollback-only SQLite write-intent restore guard (ADR 0106)

`storage.CheckInertRestoreWriteCAS` probes a fully bound, nonsecret live baseline inside a short SQLite single-writer transaction. A conditioned no-value-change UPDATE establishes the writer reservation; the full in-transaction fence rehashes committed applied/LKG generation blobs, current declaration and selected-target JSON. **Every path explicitly rolls back**; no revision, apply journal, SQLite backup payload, configuration, or runtime core is changed. `CheckInertRestoreWriteBoundary` runs after repeated authenticated candidate checks and rejects selection/declaration changes immediately before the write-intent CAS. Separate-writer contention, fault/cancellation and SIGKILL regressions verify SQLite lock release. This remains a **rollback-only check, not a durable transactional restore or a write CAS coupled to import**, and never sets `RestoreSupported` or `RestoreReady` true.

## M4 schema v18 inert restore preparation journal

ADR 0107 adds a **separate SQLite v18** `inert_restore_preparations` table holding only nonsecret hashes, a safe encrypted candidate basename and canonical digest-bound live CAS snapshot. The atomic guarded SQLite write-CAS and **INSERT share one committed transaction**; failed checks roll back before changing any live generation, apply journal or sing-box process. Only one pending row and 32 total rows are permitted. A restart can read it, but `RequiresRevalidation=true` always and only fresh candidate flock + full encrypted/SQLite/schema/profile authentication with the original key can confirm it. Explicit abandon never auto-deletes ciphertext. Old v17 encrypted archives remain accepted for **read-only preflight** against a separately migrated v17 schema; new snapshots use v18. Snapshots that contain active inert preparation records fail closed. This is an INERT durable record, **not** a restored/activatable backup, and `RestoreSupported=false` / `RestoreReady=false` remain fixed. A v17 executable cannot open a newly migrated v18 live database.

## M4 journal-bound encrypted resource lease (ADR 0108)

SQLite remains **schema v18**. `CheckInertRestoreRecordCAS` obtains a short SQLite write reservation but unconditionally rolls back after atomically matching the full persisted pending journal row (including ID/phase/timestamps and digest-bound baseline) with the live applied/LKG/selection/declaration/core state. `AcquireInertRestoreResourceLease` reacquires the known encrypted candidate's private Linux directory flock after restart, resupplies the archive key, fully authenticates ciphertext and the in-memory database, and pins its regular 0600 single-link file inode **for the lifetime of this process only**. A same-byte inode substitution, incorrect key, altered journal, active application, or changed live selection fails closed, without deleting ciphertext. SIGKILL drops flock; only the inert metadata and ciphertext persist, so fresh acquisition is mandatory. This is not a durable cross-restart OS lock, backup importer, activation receipt, dual rollback, or actual restore. Both restore capability flags remain false.

## M4 stable archived lifecycle attestation (ADR 0109)

The immutable WAL-consistent closure builder and independently authenticated sealed archive reader now share a strict SQLite archived-domain/lifecycle audit. A backup snapshot with any **active apply attempt**, pending recovery requirement or v18 inert preparation is rejected before encryption; sealed archives with these inconsistencies are rejected even if their HMAC and resource digests are correct. For a configured daemon, the current Applied and LKG generation IDs must have exactly one matching `committed` record across `apply_journal` and retention-compacted `apply_history`, and the applied target revision must match `config_revision` (LKG cannot be newer). An initial unconfigured SQLite image is inspectable but contains no restorable generation. This does not authorize any restore/import/core operation; `RestoreSupported=false` and `RestoreReady=false` remain enforced, and the 64 MiB in-memory SQLite preflight cap is unchanged.

## M4 anonymous restore resource probe (ADR 0110)

An internal, **non-activating** `InertRestoreResourceLease.ProbeAnonymousResources` now tests actual resource materialization from journal-bound encrypted candidates into one unnamed, UID-private Linux `O_TMPFILE` inode at a time. Each verified rules/core inode must have `nlink=0`, no execute permission, a bounded exact SHA-256/length and a second independent read-back digest before close. The whole archive remains MAC/SHA-bound, the ciphertext flock is held for the entire operation, the live journal and complete CAS are rechecked before and after, and no pathname or resource FD is returned. Existing encrypted backups and the daemon remain unchanged. A separate, pre-existing 0700 scratch directory and O_TMPFILE-capable filesystem are mandatory; no unsafe fallback is attempted. The credential-bearing SQLite plaintext is not extracted and the existing 64 MiB read-only in-memory SQLite preflight cap remains. This validates only **transient materializability**, not forensic erasure, durable cross-restart leases, restore, import, or execution; both restore flags remain false.

## M4 portable in-memory rule-path relocation preview (ADR 0111)

A new **internal-only**, journal-bound `PreviewPortableRulePaths` audits authenticated archived SQLite again in memory and traverses the bounded historical native configurations. It checks the compiler-owned original SHA/manifest and exact `route.rule_set` bindings against the signed-and-hashed inventory, then hypothetically substitutes only each local rule path with a target-state-root-relative content-addressed absolute path. It emits only deterministic content hashes and counts, never credential-bearing native JSON, source paths or usable resource handles. A no-op source-root preview preserves the existing digest; mixed retained generations without rules do not gain new bindings. The supplied target directory is **lexical only and is not opened or trusted**; therefore success does **not** prove resource availability, migration feasibility, or permission to activate. The source SQLite/selection/declaration/LKG and sing-box process remain untouched, and no external restore/TUI/API is exposed. `RestoreSupported=false`, `RestoreReady=false`, T15/T23 and all stable-release prerequisites remain unchanged.

## M4 read-only destination rule-tree audit (ADR 0112)

The private `InertRestoreResourceLease.InspectPortableTargetRuleTree` now checks an **existing** prospective Linux target state root and its rule-set directories through component-by-component `openat(O_NOFOLLOW)` descriptor pins. The target root and `core/rule-sets/sha256` must be current-UID-owned 0700 real directories. Every already-present content-addressed rule file is checked for exact canonical name, size, SHA-256, owner-private non-executable mode and single hard link, with a second independent identity/hash pass; missing files are reported, **never created or installed**. Any unsafe permission, symlink, inode replacement or live journal/Applied/LKG CAS change fails closed. The closed-on-return directory descriptors do **not** provide durable filesystem authority; a future restore writer must reacquire and validate them in a new transaction. No API, public import, restored SQLite, restart or Core activation is introduced; `RestoreSupported=false` and `RestoreReady=false` remain mandatory.

## M4 revocable in-process anonymous restore resource lease (ADR 0113)

An internal `InertRestoreResourceLease.PinAnonymousRestoreResources` can now retain the archive's authenticated rules and optional locked sing-box binary in a **bounded collection of unnamed Linux O_TMPFILE descriptors**, instead of immediately closing every test file. All resources are rehashed from independent FD reads and held non-executable with no directory entries; the credential-bearing SQLite remains in-memory-only and is never copied to a plaintext pathname. A subsequent `Revalidate` must repeat full encrypted candidate/journal/live CAS and FD/directory integrity checks; `Close` revokes them. At most one pinned bundle per live ciphertext candidate lease is allowed. No direct resource path, FD, executable handle, backup/restore API, cross-restart persistence, or activation permission is exported. Both restore flags remain false; a successful pin is **not** a durable resource transaction or a supported user backup feature.

## M4 inert atomic publication of private rule-only bundles (ADR 0114)

`InertPinnedRestoreResources.StageDormantRuleBundle` is an **internal-only, non-activating** primitive that persists verified rule files within an exclusive, private Linux staging namespace. It does **not** modify the active `core/rule-sets` tree, publish an executable Core, materialize credential SQLite, or import any database. The source anonymous resource FD stays unlinkable and is revalidated along with the encrypted candidate/journal/Applied/LKG CAS. A private `.ktui-inert-rules-pending-*` directory is fully copied, fsynced, hashed and verified for an **exact** signed-inventory file set before one `renameat2(RENAME_NOREPLACE)` publishes the inactive directory. A known existing bundle cannot be replaced; unfinished or unknown scopes are refused and never automatically recursively erased. Process crashes before rename can leave pending private scopes; crashes after rename but before parent fsync can have an ambiguous durable result, requiring future independent recovery audit. The returned receipt grants neither a durable rule lease nor any restore authority, and both restore permission flags remain false.

## M4 post-restart private rule-bundle authentication (ADR 0115–0116)

Two **internal, non-activating** checks distinguish anonymous pre-restore evidence from actual durable restoration. `InspectDormantRuleBundles` inventories at most 16 recognized private stage scopes with bounded canonical file metadata, returns no path/content and explicitly labels every completed-looking scope `published_untrusted` (`RuleBytesVerified=false`). `InertRestoreResourceLease.AuthenticateDormantRuleBundle` requires a newly authenticated encrypted candidate/journal-bound `flock`, the original explicit key, exact pending v18 journal ID and unchanged Applied/LKG/declaration/selection/Core CAS. It selects only the ciphertext-SHA-named final scope within the fixed `inert-rule-bundles` directory, rejects pending/unknown scopes, and independently verifies the *entire* expected file list, private UID/mode/inode/link constraints and actual content SHA-256/size, repeating scans and complete source/CAS checks. A successful `RuleBytesVerified=true` report has only in-call validity and **never grants a persistent FD/lease, cleanup/overwrite authority or restore/import capability**. Wrong keys, altered bytes, symlinks, missing/extra rules, same-byte late inode substitutions, live changes and subprocess crash/reacquisition are covered by regression tests. No user-facing restore or active rule/Core/SQLite publication is supported; `RestoreSupported=false` and `RestoreReady=false`, T15/T23 and long-running release gates remain open.

## M4 authenticated dormant-rule quarantine (ADR 0117)

The internal `InertRestoreResourceLease.QuarantineDormantRuleBundle` requires an explicit, non-authorizing ADR 0116 expected report and freshly reauthenticates the complete journal-bound encrypted candidate/inventory, live CAS and every exact content-addressed file before a **single** `renameat2(RENAME_NOREPLACE)` transitions the dedicated, inactive private `.ktui-inert-rules-v1-<SHA>` directory to `.ktui-inert-rules-retired-v1-<SHA>`. No caller-chosen path is accepted. It rejects pending/unknown scopes, inode replacements, permission/hardlink/hash damage, wrong keys, stale journal/selection and destination collisions. Rename success is verified with directory/file hashes, inode identities and fsync; a SIGKILL or error after rename but before durable fsync does not authorize deletion, retry, rollback or adoption. The retained 0400 rule files are not physically removed. The retired namespace intentionally blocks ADR 0114 publisher and ADR 0115 ordinary inventory until an independently reviewed explicit recovery/physical-reclamation mechanism exists. No live rule/Core, secret SQLite, apply journal or running proxy state changes; `RestoreSupported=false`, `RestoreReady=false`, full restore T15/T23 and long-term release gates remain open.

## M4 authenticated retired-rule inspection and reclaim namespace (ADR 0118)

The isolated `inert-rule-bundles` namespace has a new **read-only** post-restart integrity path for already-retired rules. It requires the exact pending v18 journal, fresh ciphertext `flock`, explicit archive key, repeat full HMAC/SHA and SQLite profile/schema checks, live Applied/LKG/selection/Core CAS and full per-rule SHA-256 verification through private O_NOFOLLOW directory/file descriptors. Other complete private published/retired scopes are scanned as untrusted shapes; pending, unknown, symlink and already-reclaiming scopes refuse. A separate explicit, CAS-bound `BeginRetiredDormantRuleReclaim` can atomically change only the retired scope's name to a private `reclaim-v1` directory; it revalidates the whole original authenticated byte set, uses `renameat2(RENAME_NOREPLACE)`, re-verifies, and fsyncs. No unlink, recursive removal, TTL-based GC, active ruleset movement, SQLite import, Core start, restored generation or automatic crash continuation exists. The report deliberately says `BytesDeleted=false`, `RestoreSupported=false`, `RestoreReady=false`. The physical-deletion state machine and power-loss recovery remain blocked release gates (ADR 0118).

## M4 signed per-leaf inactive-rule physical reclaim (ADR 0119)

A new internal-only HMAC-signed immutable plan binds the encrypted archive/inventory digests, exact still-pending v18 recovery journal ID, private reclaim-scope inode and every original 0400 rule's name, size, SHA-256 and device/inode. Only after `fsync` of that plan can an explicit single-rule cleanup call publish its **own** 0400 per-index HMAC intent, fsync it, independently rehash the named existing file and live Applied/LKG/declaration/selection/Core CAS, then issue a single no-follow/parent-descriptor-relative `unlinkat` and fsync the scope. A restarted inspector accepts a missing original rule **only** with its matching signed per-file intent and otherwise fails closed; the original ciphertext and live journal must still authenticate. No `RemoveAll`, background GC, unverified orphan deletion, target rule publication, Core execution, live SQLite migration, final reclaim-scope removal or operator-facing command is enabled. Reports distinguish authenticated unlinked byte lengths from guaranteed free filesystem blocks and keep `RestoreSupported=false`, `RestoreReady=false`. Full power-loss/long-running T15/T23 and eventual active restoration remain blocked.

## M4 terminal signed completion of private rule reclamation (ADR 0120)

Internal `SealCompletedDurableReclaim` is an explicit, lock-held, non-deleting terminal transaction. It first independently checks original ciphertext HMAC/inventory/SQLite schema, exact prepared v18 journal and live Applied/LKG/declaration/selection/Core CAS. Every original 0400 rule must already be absent **only under its immutable authenticated per-leaf unlink intent**, and the reclaim scope must have no unknown entry. It O_EXCL-creates/fsyncs a private, per-archive-key domain-separated HMAC completion marker containing the original plan SHA, journal ID, directory dev/inode and exact rule count/absent lengths, then repeats the complete namespace and live CAS checks. A separate post-restart `InspectSealedDurableReclaim` accepts **only** the original immutable plan, every authenticated intent and the completion marker; the pre-completion ADR 0119 readers and unlink methods intentionally reject it. The signed plan, intents and final evidence are intentionally **retained**, and no unverified final directory cleanup/auto GC, active Core/rule changes, credential SQLite restore, or API/CLI/TUI backup/recovery route exists. The reports are not durable inode locks or restore authority: `RestoreSupported=false`, `RestoreReady=false`. Physical final metadata deletion and T15/T23 power-loss replay remain gated.

## M4 off-scope independent terminal reclaim attestation (ADR 0121)

For an *already sealed*, still completely retained ADR 0120 inactive reclaim scope, internal `AttestSealedDurableReclaim` can write **one extra immutable signed audit anchor outside that scope**, directly under the private existing live SQLite parent. The destination is derived from the live state path, never supplied by an archive or CLI. A dedicated HMAC domain binds the exact original archive/inventory, immutable plan, completion marker, v18 prepared journal ID, private scope device/inode and original rule count/absent byte lengths. Creation is exclusive, private, no-follow and fsynced; duplicate, wrong-key, tampered, missing original-proof or stale live CAS conditions refuse. `InspectRetainedReclaimAttestation` requires the original ciphertext key and fresh flock lease even after restart and compares original proof and external anchor inode identities across two complete authenticated scans. A Linux child SIGKILL fixture checks reinspection of visible marker evidence when killed after file fsync and before parent-directory fsync. No crash fixture constitutes a real power-loss replay, and the off-scope marker **never** authorizes deletion of the original evidence or itself. No automatic GC, restore/import, Core activation or public backup/recovery/cleanup API has been added; `RestoreSupported=false`, `RestoreReady=false`. T15/T23, final metadata retention/deletion policy and other documented release gates remain blocked.

## M4 immutable full-proof copy outside terminal reclaim scope (ADR 0122)

An additional **internal-only, explicit, non-deleting** `MirrorSealedReclaimEvidence` step protects the **complete authenticated terminal audit history** before any future operator-reviewed cleanup can even be considered. After independently verifying the original ciphertext, sealed plan, *every* per-leaf deletion intent, completion marker, ADR 0121 independent attestation, still-prepared v18 journal and unchanged live CAS, it writes at most one immutable, owner-private 0400 mirror in the already-existing live SQLite state directory. The canonical, HMAC-authenticated (separate domain) body embeds the full original plan, completion and external anchor bytes plus ordered intent names/MAC values; it binds exact ciphertext/inventory hashes, scope dev/inode, journal ID, rule count and authenticated absent bytes, with a strict 256 KiB cap. `InspectMirroredReclaimEvidence` independently reacquires the original ciphertext lease after restart, rechecks **all** original source evidence and the two off-scope proofs, and compares two complete scans of their inode identities. Fault injection covers duplicate, missing/tampered originals, symlink/public/altered mirror, stale selection/live state and SIGKILL after mirror file fsync but before parent-directory fsync; real approved Core integration verifies current rule files and generation remain untouched. The mirror is **not** usable without the originals, is not an authorization token for deletion, and does not provide power-loss evidence. No metadata unlink/rmdir, backup import/restore, Core Check/Activate/Verify, automatic GC or public backup/cleanup entrypoint is available. `RestoreSupported=false` and `RestoreReady=false` remain mandatory; release blockers including T15/T23 and offline CN rule licensing are unchanged.

## M4 source-independent signed proof audit, without cleanup authority (ADR 0123)

A separate internal read-only `InertRestoreResourceLease.InspectDetachedReclaimMirror` can authenticate the **historical signed terminal reclaim evidence** in the private ADR 0122 mirror **without opening the original inert reclaim scope**. It does not relax the original 32-byte ciphertext key, full encrypted archive and in-memory SQLite profile/schema checks, exactly prepared v18 journal ID, current Applied/LKG/declaration/selection/Core CAS or UID-private no-follow directory and file rules. The verifier checks canonical JSON, independent domain-separated HMACs for the outer mirror, original plan, terminal completion, ADR 0121 attestation and *every* exact sorted three-digit per-leaf intent, verifies archive inventory/SHA/size/scope inode and count/byte relationships, then compares two complete external marker/mirror inode and content reads. The original source-bound inspector is unchanged and continues to refuse missing source evidence. A new independent lease succeeds against historically authenticated proofs when the original source namespace is moved aside for testing, **without implying that the original leaf files are actually absent**. Explicit outputs force `SourceScopeVerified=false`, `RuleAbsenceVerified=false`, `DeletionAuthorized=false`, `RestoreSupported=false` and `RestoreReady=false`. The mirror is *not* a deletion authorization or restore ticket. Real power-loss T15/T23, irreversible cleanup/tombstone retention policy and all other M4 release gates remain blocked.

## M4 read-only retention review and no-deletion policy (ADR 0124)

A new **internal-only, non-authorizing** `ReviewTerminalReclaimRetention` contrasts ADR 0123's source-independent *historical signature* verification against ADR 0122's complete **current original-scope** inspection. With the original encrypted archive/key, exact prepared v18 recovery journal and unchanged live Applied/LKG/selection/declaration/Core CAS, the review authenticates detached evidence, attempts current source verification, then independently reauthenticates history. If any source scope proof is missing, changed, unsafe or inaccessible, the report says only `SourceStatus="unverifiable"`, `SourceProofsVerified=false`, even when the HMAC historical mirror is valid. If both agree on all digest/byte/count identities, it may report source evidence verified. **Neither state** ever grants physical cleanup, retention policy approval, power-loss certification, restore readiness or Core activation. It never writes a file and never returns path/secret/rule payloads.

The cumulative race-instrumented backupclosure fixture suite previously exceeded its 30-minute single-process deadline on one GitHub Actions runner. CI now dynamically enumerates all Test/Fuzz/Example entrypoints and runs four disjoint complete `-race` shards plus all other Go packages once, with no skipped encryption or SQLite cases. Ordinary tests/Vet/build and real approved Core integration remain separately required. Actual power-loss T15/T23, terminal metadata deletion and release soak/operational gates remain blocked.

## M4 retained-evidence capacity observation (ADR 0125)

The internal `InspectReclaimEvidenceFootprint` method performs a strictly bounded **name-only and byte-size census** of private ADR 0121 attestation and ADR 0122 full-mirror files across the pre-existing UID-private `0700` SQLite state directory. It requires the original sealed candidate/key, prepared v18 journal and live Applied/LKG/declaration/selection/Core CAS and checks no-follow owner-only `0400` single-linked file identities and contents twice. The directory review fails closed above 4,096 total entries, 256 matching evidence entries or 40 MiB of matching proof data, as well as on malformed digest basename, symlink/hardlink/public file or concurrent replacement. It returns only counts and bytes; **it cannot cryptographically verify other archives' signatures merely by matching filenames**. It does not write, delete, enforce a global quota or determine eligibility for retention/cleanup; all cleanup/restore readiness flags remain false. Actual cross-writer quota locks, operator retention policy, T15/T23 power-loss tests, final metadata cleanup and full recovery transaction remain blocked.

## M4 cross-candidate proof-publication guard (ADR 0126)

ADR 0125's name/byte census is now reused inside an advisory `flock(LOCK_EX|LOCK_NB)` on the **existing** UID-private SQLite state directory, shared by both known ADR 0121/0122 explicit external proof writers. This addresses the race between two *independently leased* encrypted candidates testing a single global parent for capacity. Under the held directory lock, publication requires full original ciphertext/SQLite/schema/profile, v18 prepared journal and live CAS, two complete bounded source-directory proof counts, prospective 4,096 total parent entries / 256 matching proofs / 40 MiB total proof bytes, a second pre-openat scan, `O_EXCL|O_NOFOLLOW` 0400 publication and file+parent fsync, plus two complete post-publication proofs that all old inode/byte identities remain and exactly one expected file appears. An uncertain post-fsync result never grants success or triggers file deletion. No lockfile, automatic GC, TTL, orphan adoption, physical source cleanup, credential import, active Core transition or public restore entrypoint is added. The lock is **advisory** and does not impose a hard quota on out-of-band writers ignoring it; ADR 0125's read-only `QuotaEnforced=false` remains accurate. T15/T23 and long-duration soak are still open.

## M4 conservative read-only proof hold classification (ADR 0127)

`InertRestoreResourceLease.InspectRetainedEvidenceTriage` is an internal, non-deleting, non-restoring preflight that takes an advisory **shared** state-directory flock, then reconciles **twice** the current original archive's full signed source/detached historical evidence and the strictly bounded global attestation/mirror filename census. It requires the original key and still-prepared v18 journal and live Applied/LKG/declaration/selection/Core CAS; it neither opens nor validates foreign encrypted backups. A name-only foreign proof cannot be promoted to signed identity. The report classifies missing source, unmatched evidence names, insufficient arithmetic headroom for the maximum allowed future proof pair, or the default absence of an approved retention policy. All outcomes require manual hold and explicitly set policy approval, actual power-loss evidence, deletion permission, and restore readiness to false. The shared advisory lock prevents **cooperating ADR 0126** writers from interleaving, not noncooperating filesystem actors or future inode drift. No age-based expiry, automatic recovery/GC, source metadata unlink/rmdir, Core Check/Activate/Verify, or public backup/cleanup action is introduced.

ADR 0127 security regression: equal global file counts/bytes cannot detect a same-byte inode replacement. The manual review therefore retains a complete before/after descriptor-scanned private proof identity set across both authenticated reviews and both footprint reports, reconciles exact current archive attestation/mirror bytes to signed SHA identities, and rejects changed identities of **unrelated** proof-looking files as well. Any detected TOCTOU returns no report; no cleanup is authorized.

## M4 experimental guest SQLite post-stop read-only subset (ADR 0129)

For an explicitly isolated non-root disposable VM only, a bounded `scripts/recovery_lab/guest_reboot_audit.py` captures and independently compares the v18 guest SQLite Applied/LKG config/manifest/source-map SHAs, selection state, committed revision, Core intent, `integrity_check`, FK and journal presence across an externally triggered virtual guest interruption. It requires the exact per-VM/case/nonce operator acknowledgement, a private fixed witness scope, independently pinned prior baseline SHA and the ADR 0128 forced-stop observation. A matching SQLite *subset* is **not** a physical power-loss replay, full schema/resource/backup HMAC audit, Core traffic test, or restart attestation; all restore, cleanup, power-loss, reboot and Core-health verification fields remain false. Real T15/T23 with post-reboot failure injection and T25 long-run stability remain outstanding.

## M4 actual v18 guest prepared journal checkpoint fixture (ADR 0130)

Unlike the host-side marker-only ADR 0128 lab, the Linux Go-test-only `TestT15DisposableGuestPreparedBoundary` generates the phase marker **after** the application's own `storage.Open` v18, committed baseline and independently fsynced second prepared-but-never-activated journal. Access requires exact operator guest acknowledgement and empty disposable private state, refuses production/existing SQLite files, symlinked or stale paths and duplicate markers, and never stops a VM or Core itself. Ordinary CI validates production `RecoverInterrupted` only on a synthetic private guest database; a manual guest's still-active pre-reconciliation journal must be held for separate after-boot inspection. Marker presence is not proof of physical power loss, reboot integrity, Core health or recovery permission; all public restore/cleanup gates remain disabled.

## ADR 0131 cross-language real schema regression

M4's guest read-only SQLite check is now exercised against databases made by the actual Go v18 migrations and application journal APIs, rather than trusting synthetic Python schemas alone. The real Go/Python pair must agree on applied/LKG and selection digests and *fail closed* for unresolved prepared apply, changed live selection or forged virtual-stop identity. A fabricated, no-authority stop JSON in ordinary CI is strictly **test input** and never certifies a guest reboot, physical power loss, active Core, encrypted archive authentication, rollback, restore or metadata deletion.

## ADR 0132 narrow post-RecoverInterrupted guest SQLite subset

The disposable-only Python `guest_reboot_audit.py` now pins **format 2** baselines with a digest-bound latest pending generation and redacted apply-journal identity. In `T15-prepared-journal` only, `reconcile-verify` can affirm the limited, separately executed real Go Store `prepared → interrupted` journal change while refusing drift in confirmed Applied/LKG, selection, Core intent, routing mode or candidate payload (including matching rehash attempts). Normal `verify` still requires an exact before/after snapshot and refuses the recovered version. Older pinned v1 baselines cannot silently upgrade. The result grants **no** VM-stop, reboot, physical power-loss, restore, HMAC, Core, metadata-deletion or release authority; full P0 compatibility and recovery remain pending.

## ADR 0133 T15 postactivation uncertainty remains a manual hold

Bounded Go v18 test-only recovery now covers `activating`, `verifying`, `rolling_back` and terminal failed-rollback state; it requires that `RecoveryRequired` remains set through repeated `RecoverInterrupted` and database reopen. Original confirmed generation and pending config digest remain immutable. Both Python guest replay modes must refuse the postactivation cases: a synthetic virtual-stop witness never proves actual Core restoration. No Core/route/power-failure/backup semantics are promoted from this SQLite-only evidence. T15/T23 and long soak are still open.

## ADR 0134 complete bounded archived journal metadata (guest audit v3)

An independent guest-only read-only audit now computes a deterministic digest of the complete `apply_history` metadata sequence, with a hard cap of 512 entries, validating IDs, phase/revision relation, SHA-256 fields, private error length and timestamps. It refuses malformed or oversized data. This detects changes to earlier archived rows that simple latest-record/count checks missed. Exact and `prepared→interrupted` comparisons pin the ledger, and real Go v18 `PruneRetention` fixtures test it cross-language. Prior guest v2 baseline documents must not be silently accepted. This hash is not an archived-generation BLOB audit or cryptographic HMAC, and cannot establish reboot/power loss, Core traffic, backup integrity or restoration rights.

## ADR 0135 guest inert restore journal ledger (v4 witness only)

The guest-only read-only SQLite audit now validates the full bounded `inert_restore_preparations` record inventory (max 32) and pins a private ordered digest across candidate scope, archive/inventory SHA, archive bytes, baseline JSON SHA and phase/timestamps. It rejects tampered pending records **even when the prepared row count stays 1** or a forged fence JSON is rehashed. Both prepared and abandoned records are observed, without exposing candidate names or fence payloads. Actual Go Store v18 `PrepareInertRestoreRecord`/abandonment tests verify the Python comparison contract against disposable SQLite. Baseline version v4 is incompatible with v3; no live migration occurs. This does not grant signed archive authentication, external resource lookup, restore, reboot/physical power-loss certification, Core traffic or data deletion.

## ADR 0136 canonical Go v18 inert baseline parity (guest witness v5)

The read-only Python guest auditor now matches production Go `scanInertRestorePreparation`'s strict `InertRestoreFence` schema/domain/canonical encoding, rejecting otherwise SHA-consistent but invalid inert journal baselines *before capture*. It validates all 16 exported Go fields, hashes, revision types/bounds, enum types and exact compact field order, while keeping prior 32-row limits and redacted digest-only reports. Linux Go v18 cross-language fixtures compare Go scanner and Python refusal on temporary test-only malformed canonical JSON. Guest witness v5 is intentionally incompatible with older v4 files; no product SQLite migration or user API changes. No archived ciphertext authentication, live Core, reboot, power-loss, restoration or GC claim follows.

## ADR 0137 v6 guest complete retained-generation snapshot

The test-only Python guest reader now SHA-pins every retained Go v18 `generations` row, not just current Applied/LKG/latest candidate. The inspection is bounded to 128 records and checks IDs, revision adjacency, each JSON BLOB and matching SHA-256, optional metadata nullness and bounded creation timestamps. Even a SHA-rehashed **non-current** generation or edited historic timestamp invalidates the externally pinned snapshot, demonstrated against real multi-commit Go Store v18 temporary SQLite. This is neither a production retention policy nor a migration. Old guest v5 witness files must not silently pass under v6. No pruned historical BLOB can be reconstructed, and the audit cannot authorize reboot, Core health, recovery, encrypted archive authentication or deletion.

## ADR 0138 guest v7 complete declaration-revision ledger

Guest-only read-only inspection now checks `declaration_state.current_revision` and a bounded 1..N chain of at most 128 `declaration_revisions`, including valid nonempty JSON (max 16 MiB), recomputed SHA, Go-constrained source identifier and timestamps. The new digest detects older declaration documents changed **even after rehashing** while the applied generation, newest declaration and selected target are untouched. It has synthetic Python and real Go v18 `CommitDeclaration` cross-language tests; older v6 guest witnesses are not silently reused. This does not prove complete rule/DNS compilation, external rule-resource content, Core health, reboot, electrical power loss, encrypted archive HMAC or production restore; the product SQLite schema stays v18.

## ADR 0139 guest v8 profile snapshot ledger (test-only)

The v18 SQLite `profile_state`, retained `profile_snapshots` and ordered `profile_snapshot_nodes` are separately pinned in the disposable guest read-only baseline. Each retained node payload has its BLOB SHA recalculated and full metadata recorded only in a private digest; a SHA-rehashed older node, changed pointer, invalid JSON or ordinal causes refusal. The fixed budgets (64/128/8192 rows and 48 MiB node bytes total) are for this disposable experiment, **not** product quotas. The Go v18 integration regression commits two real profile snapshots and verifies failure for a replaced previous node. Live `profile_sources`, user overlays, original subscription content and external resources are not yet authenticated by this ledger. Baseline v8 cannot interpret v7 or older witnesses; T15/T23/T25, Core/VM restart, archive HMAC, actual restoration and long soak are still unverified.

## ADR 0140 guest v9 persisted node-overlays ledger

The read-only v18 SQLite guest records all `profile_node_overlays`, including detached overrides for removed nodes whose source keys may return. Each entire row (identity, revision, disabled/favorite, alias, nullable rank, timestamp) is validated against the Go model and included only through an ordered digest in the guest witness; a silently changed dormant override without a CAS-revision increment invalidates the external pre-stop SHA. Maximum 2,048 overlay rows applies only to this disposable audit, not the 8,192-per-profile production limit. Python synthetic tests and a real Go Store v18 cross-language fixture check the normal and adversarial paths. Guest baseline v9 is incompatible with older v8 witnesses. Separate `profile_sources` data, Core/VM restart, encrypted archive authentication, credential restoration and T15/T23/T25 acceptance remain unverified.

## ADR 0141 guest v10 complete persisted subscription source evidence

The guest-only audit additionally hashes **all 33** `profile_sources` columns (including URLs, fetch rules, filters, scheduled updates, update leases, HTTP metadata, retry counters and `Subscription-Userinfo` fields) into a private digest. Source records may exist without snapshots. A changed remote URL or usage counter with unchanged source revision must fail against a previously pinned SHA; the guest also refuses malformed fields/lease pairing or more than 64 sources (test-only cap). Real Go v18 source/lease/usage transactions and Python observer test this. Standalone `RecoverInterruptedProfileUpdates` is not an allowed transition of the narrow T15 prepared-apply-only reconciliation; any source drift requires manual review. No URLs/tokens are emitted in reports. Prior v9 witness files must not be reinterpreted as v10; the production DB stays v18. Provider authenticity, Core, physical VM/power-loss durability, archive HMAC, credential restoration and T15/T23/T25 remain unverified.

## ADR 0142 host phase/stop-intent binding (guest v11 only)

The guest `capture` requires a private, exact `ready-<nonce>.txt` matching `vm_power_cut.marker_body(case,nonce)` and puts its SHA-256 into the pre-stop external-SHA-pinned baseline. Both read-only `verify` and `reconcile-verify` now fail closed unless complete, private `intent` and `observation` records match the pinned marker, identity, known schema/fields, strict all-false privilege flags and chronological UTC stamps. Two reads catch receipt alteration during observation. Synthetic Python tests call the actual mock-libvirt host producer; real Go v18 SQLite regression rejects an absent host intent despite intact configuration. This is **not** a new production migration, guest restart attestation, hardware durability proof or restoration/cleanup permission; previous witness v10 must not be reused.

## ADR 0143 non-destructive libvirt running observer + guest v12

The host can now record a one-shot user-session libvirt **running** observation *after* the operator manually starts an isolated disposable guest; default is read-only/no writes, `--record` requires an exact non-root acknowledgement tied to the independently pinned pre-stop guest baseline SHA. Guest v12 extends v11 phase→intent→stop continuity with exact private poststart SHA links, duplicate-key refusal, strict UUID/clock/keyset/false flags and repeat inspection. Python fake-libvirt producer/consumer regressions and real Go SQLite v18 cross-language tests cover the path. No script starts/stops a VM in CI, no physical loss/guest OS boot/Core/HMAC/restore/deletion approval is inferred and no production schema or quota changes. Old guest v11 witnesses cannot be silently reinterpreted.

## ADR 0144 independent kernel boot epoch (guest lab-only)

A separate guest `boot-epoch-<nonce>.json` is captured from the real Linux procfs boot UUID **before** host stop and SHA-pinned outside the VM. Later verification requires the actual procfs boot UUID change and exact original guest v12 baseline, private epoch record, host stop intent/observation and poststart hash chain. No test or production CLI supplies an override boot ID; only in-process Python synthetic regressions mock the reader. The real Go v18 Store cross-language test must reject an unchanged CI kernel even if matching synthetic host receipts exist. No new production migration or quota; guest SQLite baseline remains v12, separate boot-epoch evidence is v1. The tool cannot certify hypervisor-level reboot, physical power fault or Core/HMAC/restore/metadata deletion. T15/T23/T25 and release gates remain OPEN.

## ADR 0145: bounded T24 CN asset provenance-only preflight

A Linux `openat`/O_NOFOLLOW audit of the pinned Karing CN source closure now enforces descriptor-relative family/filename whitelisting, no symlink/hardlink/FIFO/empty files, stable name/inode/mtime/ctime and 8 MiB per-file / 64 MiB total read limits. Its PR audit workflow verifies the exact Karing checkout SHA and the clean source tree before/after generating a JSON source/hash manifest; it leaves license/redistribution explicitly **blocked** and the single `geoip:bing` upstream absence unresolved. This only tests pinned resource *inventory integrity*, not a redistributable package, actual CN offline startup, or a successful T24. Runtime core/SRS mapping and five-layer/region route semantics are untouched; future work needs license provenance, approved distribution format and amd64/arm64 truly offline boot+resource tests.

## ADR 0146 — Native no-network management bootstrap (T24 partial)

Both native Linux architectures now exercise the actual compiled CLI/Daemon under an unprivileged Docker network-none sandbox, checked for no effective capabilities or outbound route. It performs approved Core version and inert config check, twice opens isolated SQLite via Unix-socket Daemon startup, and asserts no Core activation/recovery or distribution-capability escalation. Dependencies, OCI image and binaries are pre-staged by connected CI before the airgap; the test is **not** a full offline distributable tar, currently applied Core live-traffic, DNS path, CN 67-SRS resource archive, actual provider license review, offline data update or rollback test. The OCI test tag remains mutable; provenance alone cannot be advertised as a release-locked environment. T24 and full M5 release remain open.

## ADR 0147 — independent native network-none Core loopback data-plane test

The approved Core is now started independently in a nonroot, no-capability, read-only Docker network-none container on native amd64 and arm64. Each of three localhost mixed inbounds must complete real SOCKS5 CONNECT/payload echo to a same-container ephemeral 127.0.0.1 server, with local API 401/authorized version checks. OCI test image is pinned by the observed multi-arch index digest; CI host stages/downloads/builds before isolation. CN SRS, DNS, external node routing, production Daemon-Core activation and redistribution remain untested/unapproved; T24 full release OPEN.

## ADR 0148: disconnected verified-Core Daemon cold-start refusal

The native amd64/arm64 T24 preflight now includes a separate `KARING_TUI_CORE_PATH` configured Daemon in the zero-network, ordinary-user sandbox. A verified Core binary must remain dormant without an applied generation, even when an explicit test-only start command fails. The test resets the failed durable intent with an explicit stop and checks private persistent control secret/SQLite state across Daemon restart; substituted or symlink binaries must be refused. This is only a management-plane safety boundary, not an applied-generation traffic or full offline CN release test. T24 and licenses remain blocked.

## ADR 0149 — native network-none real managed applied generation

A fourth independent native amd64/arm64 zero-network container now exercises actual Daemon Unix API commit/compile/apply of a synthetic non-CN V1 declaration, explicit approved Core start/stop, and real local SOCKS5 traffic from all three configured inbounds (including a temporary selected local SOCKS node). It checks persisted generation and a stopped Daemon restart without network or special permissions. This does not certify real CN rule assets, public proxy/DNS connectivity, offline redistribution, full T24 or recovery/power-loss trials. Existing permissions and license flags remain unchanged.

## ADR 0150/0151 — native managed route separation and selected failure isolation

The fourth native network-none Daemon-managed Core sandbox now counts use of the **single synthetic local SOCKS node** per inbound: Rule/Direct must never traverse Selected, while Selected must traverse exactly once per healthy cycle. ADR 0151 adds a deliberate SOCKS5 CONNECT refusal from that selected localhost fixture. During refusal the other two inbounds must remain independently functional; Selected must not report successful CONNECT, and the approved managed Core must remain on the same PID and persisted applied generation. Re-enabling the local node must restore the selected route both before and after restarting the Daemon on the same disposable SQLite. This is a synthetic application-level failure test only: no real CN rules, remote DNS/proxy, redistribution approval, two-rollbacks or offline tar release is implied. T15/T23/T24/T25 remain OPEN.
