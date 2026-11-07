# ADR 0167 — held HTTP CONNECT tunnels close on supervised Core crash (T22/T25 partial)

- **Status:** bounded real native Core lifecycle preflight, not complete T22, restore or soak.
- **Depends on:** ADR 0160 single pidfd-supervised Core crash with three held SOCKS5 sessions, and ADR 0166's three held HTTP CONNECT explicit-stop audits.
- **Envelope:** the existing sixth/approved managed Core in the same fourth linux amd64/arm64 nonroot, read-only, cap-drop, `docker --network none` container. Same pinned PID and Approved config/declaration revision 2, Applied=LKG, ephemeral numeric localhost echo and Selected synthetic SOCKS node. No extra SIGKILL, Core restart, privileges, port, license, external DNS or TUN.

## Gap and decision

ADR 0160 verifies old SOCKS5 TCP sessions do not survive one supervised Core crash; ADR 0166 verifies old HTTP CONNECT tunnels do not survive explicit stop. A distinct HTTP CONNECT tunnel handling path may behave differently during a Core process crash.

1. During ADR 0160's **existing one pidfd-supervised SIGKILL** and crash recovery, hold **six** live localhost tunnels concurrently: the three preexisting SOCKS5 sessions and one new numeric 127.0.0.1 HTTP/1.1 CONNECT session per Rule:2080, Direct:2081 and Selected:2082. Each HTTP tunnel must first receive a complete bounded HTTP 200 and exact application echo. The three original SOCKS5 streams remain untouched.
2. Require no unexpected synthetic Selected node accepts from Rule/Direct, and exactly **two** new Selected upstream successes across the six held tunnels (one SOCKS5, one HTTP), no new refusal or failed node. Before allowing the preexisting single kill, recheck the actual Core PID/config/declaration revision 2 and Applied=LKG; refuse SIGKILL against any changed or unowned process. No retry or additional fault injection.
3. After **the same** pidfd-supervised crash/restart and its earlier recovered-routing probes, each of the three old SOCKS5 and three old HTTP streams must yield EOF/reset/abort within three seconds. No byte, stale relay or timeout is acceptable. The only healthy traffic afterward must originate from newly created Core sessions. A single ExitStack closes all six client sockets on any partial open, crash, EOF or PID error.
4. Keep the earlier supervised recovery accounting (two accepted Selected attempts and at least one refusal), so the total for this crash-stage audit becomes exactly **four** accepted Selected connections above baseline. Synthetic lifetime Selected accepts at end of the native test increase **62 → 63**. Add deterministic no-network tests verifying both protocols and all six sockets, Selected route crossing/bypass before a signal, HTTP-open exception, PID drift, a survivor of either protocol, exactly one delegated crash operation, and fixed safe error codes.
5. Only on full native amd64 **and** arm64 success emit `T22_AIRGAP_HELD_HTTP_CRASH_CLOSED=ok`. Continue emitting `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false` and `T25_72H_7D_30D_SOAK_VERIFIED=false`.

## Non-claims

This is one bounded PID-owned Core crash, not physical power loss or double rollback; not real remote proxy, DNS, UDP, HTTP absolute-form, CN five-layer/28-group licensed SRS, 1,000 reconnects, T25 72h/7d/30d soak, Restore/GC, user credentials or signed release. No TUN or subscription/ISP routing layer, `core_distribution=false`, `cn_preset_offline_bundle=false`; stable `main` unchanged. Full T15/T20/T22/T23/T24/T25 and release gates remain OPEN.


## Follow-up: exact post-crash accounting regression

The first PR #44 `f6a6148f` native amd64 **and** arm64 CI failed after the new six-held-session crash phase, at the **post-crash-stop** check, with a fixed `RuntimeError/unclassified` diagnostic. The existing post-crash ledger still required exactly **12** lifetime Selected successful accepts from the prior three-SOCKS-only workload. ADR 0167 intentionally adds one held HTTP Selected success before the same single crash, making the correct exact count **13** at this checkpoint (and **63** only after subsequent lifecycle/HTTP workloads). This is a deterministic inconsistent assertion, not a reason to waive tunnel-close, identity, route, refusal or final-count checks.

The post-crash checkpoint now calls a dedicated exact-count helper that requires `calls == 13`, `rejections >= 5`, the failure toggle off and a healthy synthetic node. Negative no-network regressions expressly reject the old **12** count, **14** (unauthorized extra path), too few refusals, active rejection, failed node and noninteger count. The exact failure message is allowlisted as a non-secret fixed `crash-post-stop-selected-accounting` code. No new retry, signal, timeout, data permission or weakening of lifecycle assertions. Fresh exact-head CI and dual native arches are mandatory.
