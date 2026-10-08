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
