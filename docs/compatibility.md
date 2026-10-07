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
| VMess | Not yet supported | Blocks complete automatic import |
| VLESS | Not yet supported | Blocks complete automatic import |
| Trojan | Not yet supported | Blocks complete automatic import |
| Shadowsocks | Not yet supported | Blocks complete automatic import |
| Hysteria / Hysteria2 | Not yet supported | Blocks complete automatic import |
| TUIC | Not yet supported | Blocks complete automatic import |
| source `route` | Intentionally ignored | Reported as `ignored_by_product_policy`; cannot create runtime RuleGroups or FINAL |
| source `dns` | Intentionally ignored for profile import | Project DNS is separately declared; source policy is reported |
| TUN / TPROXY / redirect inbound | Forbidden | Entire import rejected by proxy-only safety validation |
| `auto_route`, `auto_redirect`, enabled `set_system_proxy` | Forbidden | Entire import rejected |

Accepted node payloads are stored immutably in the profile snapshot with their SHA-256. The current and immediately previous successful profile snapshots are retained; older profile snapshots are pruned.

## Runtime node compiler

The current declaration/runtime compiler can materialize:

| Node type | Runtime status | Important boundary |
| --- | --- | --- |
| HTTP CONNECT | Implemented | Plain HTTP proxy node only; TCP |
| SOCKS4 | Implemented | TCP only |
| SOCKS4a | Implemented | TCP only |
| SOCKS5 | Implemented | TCP/UDP/both as represented by the domain model |
| Domain-valued node server | Implemented with explicit Outbound DNS | Fails closed without configured node/outbound resolver |
| TLS/Reality/advanced transport/Mux | Not yet implemented | Must not be dropped by importers |
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
- successful snapshot-to-declaration updates use declaration revision CAS and record `profile-snapshot/<id>` provenance.

Not yet implemented:

- subscription URL/fetch scheduling;
- ETag/Last-Modified fetch state;
- traffic quota/expiry metadata;
- source enable/disable/filter overlays;
- provider materialization;
- automatic scheduled declaration/apply policy after a profile refresh;
- timed update/backoff/debounce.
