# ADR 0173 — Selected HTTP CONNECT fixed-domain upstream passthrough (T22 partial)

- **Status:** proposed limited native dual-architecture experiment. Not full DNS, T22 or release approval.
- **Depends on:** merged ADR 0172 Selected SOCKS5 ATYP=3 failure isolation and ADR 0162 numeric HTTP CONNECT through managed mixed inbounds.
- **Envelope:** existing sixth approved managed Daemon/Core, Applied=LKG generation 2 and config/declaration revision 2, fourth native Linux amd64/arm64 `docker --network none --cap-drop ALL` read-only nonroot UID 10001 container. No additional Core lifecycle, real DNS lookup, public network, TUN or extra service.

## Gap

The native lab already proves *numeric-IP* HTTP CONNECT on Rule/Direct/Selected and SOCKS5 `ATYP=3` domain passthrough on Selected. It does not yet prove that an **HTTP CONNECT hostname authority** is preserved and forwarded through the real Core's Selected-to-SOCKS outbound without local DNS resolution or silent Direct bypass.

## Decision and proof

1. In the same approved sixth Daemon/Core immediately after the successful ADR 0172 Selected domain failure/recovery and before the existing final held-HTTP stop, send exactly one HTTP/1.1 `CONNECT t24-selected.invalid:<existing-echo-port>` request with an identical Host header to the existing **Selected:2082** mixed inbound. Only numeric loopback transport is dialed by the client; the fixed reserved hostname is text inside the CONNECT request.
2. Require a complete <=1024-byte HTTP/1.0 or 1.1 **200** response header, then send a bounded unique application payload and demand an exact local TCP echo response. Truncated/non-200/malformed/oversized response, wrong echo or invalid fixture fails closed.
3. Reuse the synthetic Selected SOCKS outbound from ADR 0171/0172, which accepts only that **exact reserved raw hostname** and its previously approved ephemeral echo port as `ATYP=3`, maps it locally to `127.0.0.1`, and records an independent raw hostname+port receipt. Require precisely **one** additional successful Selected upstream accept and that receipt, no new refusal or refused-domain receipt, no node failure and unchanged approved Core PID/config/declaration/Applied=LKG before and after.
4. Add no-Core regressions for request bytes/Host/Selected-only destination, valid response and exact echo, malformed/truncated/non-200/oversized replies, invalid port/payload, spoofed/missing/duplicate/wrong-name/wrong-port receipts, rejection drift, silent upstream bypass, unexpected Core restart and fixed allowlisted diagnostic labels. The synthetic node's strict domain allowlist remains unchanged.
5. Final Selected lifetime successful accepts **68 -> 69**, minimum refusals **17**. Only after the fresh exact-head ordinary CI, four Go Race shards, Managed Core Integration and fully passing native Linux amd64 **and** arm64, print `T22_AIRGAP_SELECTED_HTTP_CONNECT_DOMAIN=ok`.

## Explicit non-claims

This is **only a selected-outbound HTTP CONNECT hostname forwarding experiment against an artificial localhost mapping**, not genuine DNS queries or resolver detours, Rule/Direct hostname routing, real remote HTTP/TLS/SNI, UDP, CN five-layer/28-group licensed offline rules, 1,000 reconnects, 72h/7d/30d endurance, physical power loss, Restore/GC or release. Preserve `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, `T25_72H_7D_30D_SOAK_VERIFIED=false`, `core_distribution=false`, `cn_preset_offline_bundle=false`. No subscription/ISP route layer or TUN; stable `main` and release Draft PR #1 remain unchanged.
