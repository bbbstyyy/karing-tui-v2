# ADR 0165 — concurrent HTTP Selected refusal and same-PID route recovery (T22 partial)

- **Status:** short native network-none protocol smoke; T22 overall is still OPEN.
- **Depends on:** ADR 0163's strict (including premature CONNECT 200) Selected HTTP fail-closed semantics and ADR 0164's exact concurrent 32-byte Selected payload tags.
- **Envelope:** exactly the existing fourth native nonroot, read-only, cap-drop, `docker --network none` container in amd64 and arm64; sixth real managed Daemon, same approved Core PID/Applied=LKG generation 2, numeric 127.0.0.1 echo and synthetic Selected SOCKS node. No new port, process, privileges, external DNS, credentials, CN ruleset asset or TUN.

## Gap and decision

Concurrent successful HTTP CONNECT probes establish isolation under normal conditions, but cannot prove six overlapping HTTP clients do not silently route Selected through Direct when the Selected SOCKS upstream refuses CONNECT.

1. After ADR 0164's successful six-client/twelve-tunnel audit, check the live approved Core PID, config/declaration revision 2 and Applied=LKG. Enable only the local Selected upstream refusal flag with unconditional `finally` reset.
2. Barrier-release six concurrent HTTP clients (two per Rule/Direct/Selected, two requests each): **eight** Rule/Direct numeric-localhost HTTP CONNECT exact echoes must succeed and **four** Selected HTTP CONNECT attempts must fail closed. The Selected refusal parser keeps ADR 0163's zero-forwarded-application-data and bounded EOF/reset requirement even if the mixed inbound acknowledges CONNECT 200 early. No HTTP 200 alone establishes success.
3. Require synthetic Selected successful accepts and 32-byte Selected tags unchanged, **4–16 new recorded upstream refusals** (bounded retries), no upstream failure and no Rule/Direct traffic across the rejected Selected node. Check real unchanged Core PID/Applied=LKG after the refusal window. Any worker exception, malformed response, missing refusal, unexpected accept, new tag, excess retries, PID drift or timeout fails the test, and the refusal flag is always restored.
4. With the **same** approved Core after restoring synthetic Selected, repeat ADR 0164's six-client/twelve-successful HTTP CONNECT test; again require the four exact unique Selected tags and exactly four new successful Selected upstream accepts. Final lifetime Selected accepted count increases **57 → 61**. All previous explicit Core stop, no-listener and seventh cold Daemon stopped-intent checks remain mandatory.
5. Add deterministic no-network negative tests for invalid inputs, stale/changed PID, wrong-route accepts, missing refusal, refusal storms, tag contamination, failed upstream, worker exceptions and cleanup. On full native pass print `T22_AIRGAP_PARALLEL_HTTP_SELECTED_REFUSAL=ok`; continue printing `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false` and `T25_72H_7D_30D_SOAK_VERIFIED=false`.

## Non-claims

Not actual internet outage, throughput or p99 SLA, SOCKS hostname or DNS, HTTP absolute-form, UDP, auth, CN five-layer/28-group true resources, licensed offline distribution, 1,000 reconnects, T15/T23 physical failure, Restore/GC or T25 long soak. Full T20/T22/T24/T25 and release remain OPEN; `core_distribution=false`, `cn_preset_offline_bundle=false`, no TUN or subscription/ISP routing layer; stable `main` and release Draft PR #1 unchanged.
