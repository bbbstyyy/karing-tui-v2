# ADR 0171 — Selected SOCKS5 DOMAIN exact passthrough to synthetic local upstream (T22 partial)

- **Status:** bounded native amd64/arm64 experiment proposed, not complete T22 or release.
- **Depends on:** merged ADR 0170 fail-closed absolute-form HTTP and same-Core recovery, and ADR 0149 real native airgap managed-Core fixture.
- **Envelope:** retain the original sixth supervised Daemon/Core and fourth `docker --network none --cap-drop ALL` nonroot/read-only native container on amd64 and arm64. No new Core start, crash, privilege, real DNS server, remote host or TUN.

## Gap

The current T22 native lab exercises numeric-local SOCKS5 and HTTP, but it has not observed a **SOCKS5 DOMAIN** destination crossing Selected's actual upstream SOCKS5 transport. Code-level DNS bindings and IP-only checks cannot prove that the proxy preserves a host string or that the outbound is not silently bypassed.

## Bounded test

1. Introduce one fixed reserved synthetic name `t24-selected.invalid`. The real native client issues a SOCKS5 CONNECT on Selected:2082 with `ATYP=3`, the exact ASCII name and the existing ephemeral numeric localhost echo port. The client verifies no-auth handshake, complete successful SOCKS5 CONNECT response with supported bounded address type, and exact echo bytes.
2. Extend **only** the already local synthetic Selected SOCKS upstream to accept `ATYP=3` for the **exact fixed name and existing echo port**. Reject every different hostname/port or unsupported type before outbound dialing. The synthetic server alone maps the reserved name to `127.0.0.1` and never calls DNS. Existing `ATYP=1` accepts remain byte-for-byte restricted to their approved loopback echo/HTTP origin ports. Record a bounded raw `(hostname, port)` receipt only after successful local upstream CONNECT, under the existing node lock.
3. Before and after, verify the same approved Core PID, config/declaration revisions and Applied=LKG. On the positive path, require exactly one additional successful Selected upstream connection and one **exact** hostname receipt, no rejected upstream connections, no node failure and no changed Core. Its final lifetime successful Selected count increases **66 → 67**, and minimum refusals remain **16**. Keep the original explicit final Core stop and listener/session cleanup.
4. Add no-Core failure regressions for invalid client fixtures, rejected greeting, refused/malformed/truncated SOCKS response, exact-echo mismatch, wrong/duplicate/missing upstream hostname receipt, route bypass, unauthorized Core replacement and safe fixed diagnostic codes. Exercise the synthetic server with an actual loopback echo and verify a wrong reserved-length name or wrong target port is rejected **without any outbound dial**.
5. Only a fresh exact-head ordinary CI (including all four Race shards), managed integration and fully passing native amd64+arm64 can print `T22_AIRGAP_SELECTED_SOCKS_DOMAIN_PASSTHROUGH=ok`.

## Deliberate non-claims

This is **only Selected-side SOCKS5 DOMAIN passthrough**, not Rule/Direct hostname lookup, real DNS query/response or resolver detours, HTTPS hostname/SNI, UDP ASSOCIATE, remote traffic, CN five-layer/28-group licensed offline SRS, T20 1,000 reconnects, T25 72h/7d/30d, power-loss recovery, Restore/GC or stable distribution. Keep `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, `T25_72H_7D_30D_SOAK_VERIFIED=false`, `core_distribution=false` and `cn_preset_offline_bundle=false`; no changes to stable `main` or release Draft PR #1.
