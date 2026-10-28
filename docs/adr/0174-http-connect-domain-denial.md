# ADR 0174 — fail-close Selected HTTP CONNECT hostname refusal and same-Core recovery (T22 partial)

- **Status:** proposed bounded Linux amd64/arm64 native experiment, not full T22 or release approval.
- **Depends on:** merged ADR 0173 Selected HTTP CONNECT hostname passthrough and ADR 0172 SOCKS5 DOMAIN fail-close.
- **Envelope:** same approved sixth supervised Daemon and Core PID, Applied=LKG generation 2 with approved config/declaration revisions; same fourth `docker --network none --cap-drop ALL` read-only nonroot UID 10001 native container and its existing localhost echo + synthetic Selected SOCKS upstream. No extra Core start/stop, DNS server, WAN, SIGKILL, privileges, TUN or subscription/ISP route layer.

## Gap

Successful HTTP CONNECT hostname forwarding does not show that a refused Selected SOCKS DOMAIN upstream cannot result in a silent Direct fallback, fabricated successful tunnel, lost/rewritten hostname or unavailable Rule/Direct. Existing numeric HTTP CONNECT and SOCKS5 DOMAIN denial tests cannot substitute for the actual hostname-authority HTTP CONNECT protocol.

## Decision and acceptance criteria

1. Snapshot exact successful and rejected `(t24-selected.invalid, echo_port)` upstream receipts, Selected accepts/refusals and the **same approved running Core PID** before injecting a failure. Do not perform any client-side DNS lookup.
2. Within `try/finally` enable only the existing synthetic Selected SOCKS outbound's refusal toggle. The **Rule:2080 and Direct:2081** mixed inbounds each must complete one numeric-local HTTP CONNECT + exact echo. Neither may add a Selected successful/denied connection or any hostname receipt.
3. Issue exactly one real HTTP/1.1 `CONNECT t24-selected.invalid:<approved-echo-port>` to **Selected:2082** with matching Host, via numeric loopback transport. The client must receive either zero-byte EOF/reset/abort, a bounded complete 4xx/5xx header, **or** (because an inbound may acknowledge CONNECT before the outbound dial completes) an early HTTP 200 followed by a bounded, data-free close when sending a fixed test-only payload. Malformed, partial, oversized, 1xx/3xx, any successful application echo or stalled tunnel fails. An apparent client-side failure **alone is insufficient**.
4. The synthetic upstream must independently record **1–4** refused raw DOMAIN/port tuples, all matching the exact reserved name and echo port. Require zero additional successful Selected accepts/hostname receipts, no unexpected node failure and no false Direct fallback. Do not dial the echo target under refusal. The existing synthetic listener already records refused domain tuples before returning SOCKS5 failure.
5. Unconditionally clear the toggle in `finally` even on an exception. Recheck the original Core PID/config/declaration/Applied=LKG, then rerun ADR 0173's successful **real HTTP CONNECT hostname** tunnel through Selected. Demand exactly one new successful Selected accept, one exact successful raw-domain receipt, no extra denial or rejected-domain receipts, and no Core restart. Keep all other existing lab stages, the final explicit Core stop and session/port cleanup unchanged.
6. Add no-Core negative regressions for early HTTP 200 leaking data/stalling, bad status/headers, truncated/oversized replies, invalid target, missing/wrong/duplicate rejected hostname receipts, unexpected successes, Rule/Direct crossing, excessive/missing denials, Core PID replacement, failed recovery, toggle cleanup and fixed whitelist-only diagnostic codes. Final lifetime synthetic Selected **successful accepts 69 -> 70** and **minimum refused connects 17 -> 18**. Only fully successful exact-head ordinary CI/Go Race 4/4, Managed Core integration and native amd64 **and** arm64 may emit `T22_AIRGAP_SELECTED_HTTP_CONNECT_DOMAIN_FAIL_CLOSED=ok`.

## Non-claims

One isolated local HTTP CONNECT hostname failure/recovery is not genuine DNS query/detour/bootstrap, Rule/Direct hostname semantics, remote domain/TLS, UDP ASSOCIATE, CN 28-group/five-layer licensed offline resources, T20 1,000 reconnects, T25 72h/7d/30d soak, physical power-loss/dual rollback, Restore/GC, or signed release. Preserve `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, `T25_72H_7D_30D_SOAK_VERIFIED=false`, `core_distribution=false` and `cn_preset_offline_bundle=false`. Stable `main` and release Draft PR #1 remain untouched.
