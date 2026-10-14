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
