# ADR 0166 — established HTTP CONNECT tunnels close on explicit Core stop (T22/T25 partial)

- **Status:** bounded real Core native airgap lifecycle preflight, **not** long-running stability or full T22.
- **Depends on:** ADR 0161's explicit approved Core restart, ADR 0162 numeric HTTP CONNECT, ADR 0163 fail-closed Selected, ADR 0164 concurrent HTTP tunnels, and ADR 0165 concurrent Selected refusal/recovery.
- **Envelope:** existing sixth managed Daemon and fourth `docker --network none --cap-drop ALL --user 10001:10001 --read-only` native linux amd64/arm64 container. Reuse the approved same Core PID, Applied=LKG generation 2, existing numeric localhost echo and synthetic local Selected node. No extra Core stop/restart, SIGKILL, privileged syscall, external endpoint, DNS, license, or TUN.

## Gap

Established SOCKS5 Rule/Direct/Selected tunnels are already tested across explicit Core stop and a supervised crash (ADR 0158/0160), but **already-established HTTP CONNECT** tunnels have only been tested for successful echo and short concurrency. The HTTP parser's tunnel lifecycle could retain a TCP stream after Core stop even when proxy listeners and SOCKS5 sessions have closed.

## Decision

1. After ADR 0165's six-client Selected refusal and concurrent recovery, and **before the already existing final explicit Core stop** of the sixth Daemon, open one real HTTP/1.1 numeric `127.0.0.1:<ephemeral-local-echo-port>` CONNECT on each existing Rule 2080, Direct 2081, Selected 2082 mixed inbound. Strict ≤1024-byte complete HTTP 200 response, exact application echo, and then deliberately **leave all three sockets open**. This uses **no new listening port or core process**.
2. Each created tunnel must use only its approved route: Rule/Direct cannot add a synthetic Selected SOCKS hop; Selected must add exactly one, with zero new refusals. Re-read real Daemon Core PID, config/declaration revision 2 and Applied=LKG while the streams remain open; refuse an unexpected replacement or unsafe stop.
3. Through the **same existing** `core stop` in the pre-existing `finally`, verify persisted stopped intent, Core PID=0 and no proxy listeners. Each of the three old HTTP streams must produce EOF/reset/abort within **three seconds**; any delivered application byte or timeout is a hard failure. The node's success/refusal accounting must remain stable across stop. An inner `finally` closes every test socket even if HTTP opening, stop, status audit, EOF check or upstream accounting raises.
4. Add deterministic no-network regressions for full/partial/oversized/non-200 HTTP headers, wrong echo, invalid port/payload, live socket ownership, malformed refusal/EOF, timeout, fixed safe CI failure code mapping and successful three-socket stop cleanup. Final lifetime synthetic Selected accepted count changes **61 → 62**. Only complete native dual-architecture success may emit `T22_AIRGAP_HELD_HTTP_STOP_CLOSED=ok`; preserve `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, and `T25_72H_7D_30D_SOAK_VERIFIED=false`.

## Release boundaries

A short localhost explicit-stop experiment does **not** establish HTTP hostname/absolute-form, SOCKS domain, UDP, real CN 28-group/five-layer SRS rules and licensed distribution, 1,000 UI reconnects, p99/throughput SLA, physical loss/restore, double rollback, or T25 72h/7d/30d soaking. T15/T20/T22/T23/T24/T25 full acceptance and Restore/GC/release remain OPEN. No TUN or subscription/ISP routing layer, `core_distribution=false`, `cn_preset_offline_bundle=false`; stable `main` and release Draft PR #1 unchanged.
