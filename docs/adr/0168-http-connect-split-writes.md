# ADR 0168 — split-write numeric HTTP CONNECT header through three mixed inbounds (T22 partial)

- **Status:** bounded native protocol preflight, not full T22 or a guarantee of actual TCP packet segmentation.
- **Depends on:** ADR 0162 three successful numeric HTTP CONNECT routes, ADR 0163 failure isolation, ADR 0167 held HTTP Core crash closure.
- **Envelope:** reuse the same sixth managed Daemon and approved Core with unchanged PID, config/declaration revision 2 and Applied=LKG inside the existing fourth Linux amd64/arm64 nonroot, read-only `docker --network none --cap-drop ALL` container. No new server, Core process, port, DNS, privilege, external destination or TUN.

## Gap

Previous local HTTP CONNECT tests send the complete request header in a single client `sendall`. An HTTP mixed inbound might incorrectly depend on a single write boundary and reject a syntactically valid request delivered in multiple client writes.

## Decision

1. After ADR 0167's existing Selected refusal and 12-connection recovery checks, but before ADR 0166's held-HTTP explicit stop, issue one **real HTTP/1.1 CONNECT** each through Rule:2080, Direct:2081 and Selected:2082 to the existing numeric 127.0.0.1 ephemeral echo. Send each canonical CONNECT request as **six ordered separate `sendall` calls**, including splits within `CONNECT`, CRLF and `Host:` header. Do not insert additional sleep/retries, and do not claim that the kernel preserves the resulting TCP packet boundaries.
2. Require bounded (≤1024 bytes) complete HTTP/1.x status **200**, exact synthetic application echo, and successful socket closure per request. Fail on a missing/partial/oversized header, non-200 status, wrong echo, invalid type, empty or oversized payload.
3. Before and after the three requests verify actual approved Core PID and Applied=LKG generation. Only Selected may increment the synthetic SOCKS upstream accepted count, **exactly one** new accept across the three inbounds. Rule/Direct must never hit Selected; rejection count and node health must remain unchanged. No silent Core restart or fallback.
4. No-network unit tests verify six exact byte fragments and the reconstituted canonical HTTP request, complete echo, rejection of denied/malformed/truncated/oversized HTTP replies, incorrect echo, invalid port/payload, Rule crossing, Selected bypass, new refusal and wrong/replaced Core PID. Fixed allowlisted failure codes only.
5. Final lifetime synthetic Selected accepted count increases **63 → 64**. On complete native dual-architecture success print `T22_AIRGAP_HTTP_SPLIT_WRITE_HEADERS=ok`; retain `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, `T25_72H_7D_30D_SOAK_VERIFIED=false`.

## Explicit non-claims

Multiple client writes do not establish transport fragmentation, TCP packet timing behavior, hostname/SOCKS DOMAIN/DNS correctness, HTTP absolute-form, UDP, auth, real CN five-layer/28-group SRS assets or licenses, external routing, T20 1,000 TUI reconnects, T25 72h/7d/30d soak, physical power loss or Restore/GC. These gates and signed release remain CLOSED; no TUN or subscription/ISP layer and no change to stable `main`.
