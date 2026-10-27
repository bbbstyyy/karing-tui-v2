# ADR 0169 — airgapped numeric-local HTTP absolute-form GET (T22 partial)

- **Status:** limited native dual-architecture preflight proposed, not complete T22 or release approval.
- **Depends on:** merged ADR 0168 split-write CONNECT smoke on the same sixth supervised Daemon, pinned Core PID, Applied=LKG generation 2, declaration/config revision 2.
- **Scope:** fourth native Linux amd64/arm64 `docker --network none --cap-drop ALL`, read-only, nonroot UID 10001, no WAN or DNS; one additional ephemeral test-only **127.0.0.1** HTTP origin. No TUN, subscription/ISP route layer, privileges, additional Core cycle, SIGKILL or new management endpoint.

## Gap

Previous tests prove numeric SOCKS5 CONNECT and HTTP CONNECT tunnels, including split-write requests, but not ordinary HTTP proxy **absolute-form** requests. A proxy might handle CONNECT correctly yet misroute HTTP GET requests, bypass Selected or return a response not actually produced by the intended destination.

## Decision and proof

1. Bind one strictly local HTTP Origin with an allowlist of precisely three fixed `/t24-http-absolute-208{0,1,2}` origin-form GET request lines and matching numeric local Host header. Its handler has no DNS/network forwarding and suppresses request logging; success sends a small deterministic HTTP 200 with exact Content-Length and body. The synthetic Selected SOCKS relay adds **only this one pinned ephemeral local origin port** to its existing echo-port allowlist.
2. Through Rule:2080, Direct:2081 and Selected:2082, each send a full HTTP/1.1 `GET http://127.0.0.1:<origin-port>/t24-http-absolute-<inbound>` with exact Host and `Connection: close`. Client must receive complete <=1024-byte HTTP 200 headers, exactly one Content-Length, no transfer encoding, and precisely the expected origin body within existing bounded timeouts.
3. Confirm the real origin independently recorded exactly **one** corresponding origin-form request per inbound, in order, not an in-proxy fake response. Only Selected adds **one** successful local synthetic SOCKS upstream accept; Rule/Direct may not cross, Selected may not bypass, refusals and node failure flags must not change. Before and after, verify identical approved Core PID and declaration/config revision 2/Applied=LKG.
4. Add no-Core negative tests for invalid ports, status/headers/length/body, truncated replies, wrong Host or absolute-form at the origin, duplicated/missing origin receipt, Selected bypass and Rule crossing, Core PID drift, and fixed whitelist diagnostic codes. No raw exception, dynamic client header or private token is logged. Full native success updates synthetic Selected lifetime count **64 -> 65**.
5. Only if both native architectures pass may the test print `T22_AIRGAP_HTTP_ABSOLUTE_FORM_IP=ok`. Keep `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, `T25_72H_7D_30D_SOAK_VERIFIED=false`, `core_distribution=false`, and `cn_preset_offline_bundle=false`.

## Explicit non-claims

This is a bounded localhost HTTP forward-proxy smoke, not actual TLS, remote HTTP, hostname/DNS/UDP, CN 28-group/five-layer offline licensed rules, power-loss recovery, double rollback, Restore/GC, 1,000 reconnects, 72-hour/7-day/30-day endurance, or stable release. Stable `main` and release Draft PR #1 remain unchanged.
