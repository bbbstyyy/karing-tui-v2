# ADR 0172 — fail-closed Selected SOCKS5 DOMAIN upstream refusal and same-Core recovery (T22 partial)

- **Status:** proposed bounded native amd64/arm64 verification; not full T22 or release approval.
- **Depends on:** ADR 0171 exact ATYP=3 Selected upstream passthrough and ADR 0170 non-CONNECT HTTP Selected fail-closed recovery.
- **Envelope:** same pinned approved Core, sixth managed Daemon, Applied=LKG generation 2 and revisions 2, fourth Linux amd64/arm64 `docker --network none --cap-drop ALL` nonroot read-only container. Reuse only the already allowed synthetic SOCKS upstream, reserved `t24-selected.invalid` domain and localhost echo port. No extra Core restart, signal, DNS, public network, TUN or privileged listener.

## Gap

Successful ATYP=3 passthrough does not prove an unreachable Selected upstream cannot trigger a silent Direct fallback, a successful SOCKS5 reply, or a dropped/rewritten hostname during an upstream failure. Numeric SOCKS and HTTP failure checks cannot substitute for a real DOMAIN refusal audit.

## Decision

1. After ADR 0171's successful Selected DOMAIN probe (on the same live Core), snapshot the locked synthetic node's successful `(domain, port)` receipts, rejected DOMAIN receipts, accepted connections and rejection count. Verify unchanged pinned Core PID, declaration/config revisions and Applied=LKG.
2. In a `try/finally`, temporarily enable the existing synthetic SOCKS node's refusal toggle. Rule:2080 and Direct:2081 each must still complete an exact numeric-local SOCKS echo with no Selected accepts, rejections or hostname receipts. Selected:2082 sends one **actual ATYP=3** CONNECT carrying exactly `t24-selected.invalid` and the existing echo port. It may receive a bounded complete nonzero SOCKS5 failure code or empty EOF/reset/abort. It **must not** receive success, partial/malformed reply or timeout.
3. On rejection, the existing synthetic upstream must record each incoming refused **raw DOMAIN/port** tuple before sending its SOCKS5 error, but **never dial the echo endpoint** or count it as successful. Require 1–4 refusals (bounded Core retry tolerance), a matching list of exactly 1–4 new rejected hostname receipts, unchanged successful hostname receipts and successful-accept count, and no node fault. If the client appears refused but the node sees no exact-domain refusal, fail closed.
4. Unconditionally restore the refusal toggle in `finally`. Verify the same Core PID/Applied=LKG without restarting it; rerun ADR 0171's successful real Selected ATYP=3 request, require exactly one additional successful upstream accept, one additional exact successful domain receipt and **no** further denial or rejected-receipt drift.
5. No-Core regressions reject wrong/missing/duplicate refused receipts, healthy Rule/Direct using Selected, Selected direct bypass/success, malformed/incomplete/timeout replies, excessive/missing retries, node faults, Core replacement, invalid fixtures and unsuccessful recovery. A real local synthetic server test proves that rejected DOMAIN requests produce the exact SOCKS5 error and **zero** outgoing dial. Only fixed allowlisted diagnostic codes may be printed.
6. Final lifetime synthetic Selected successful accepts **67 → 68**; minimum denied CONNECTs **16 → 17**. Only complete new exact-head ordinary CI (Go Race 4/4), Managed Core Integration and both native architectures can emit `T22_AIRGAP_SELECTED_SOCKS_DOMAIN_FAIL_CLOSED=ok`.

## Explicit non-claims

This experiment only proves fail-closed Selected SOCKS5 DOMAIN traffic in one offline loopback fixture. It does **not** prove Rule/Direct hostname DNS, actual resolver queries or detours, remote hostname/TLS, SOCKS UDP ASSOCIATE, CN 28-group/five-layer licensed SRS, T20 1,000 reconnects, T25 72h/7d/30d, real power loss, Restore/GC, distribution completeness or stable release. Preserve `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, `T25_72H_7D_30D_SOAK_VERIFIED=false`, `core_distribution=false` and `cn_preset_offline_bundle=false`; do not modify stable `main` or release Draft PR #1.
