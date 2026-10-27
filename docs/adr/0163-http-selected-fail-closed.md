# ADR 0163 — HTTP Selected upstream fail-closed / recovery (T22 partial)

Status: bounded native network-none protocol preflight, not full T22.
Depends on: ADR 0162 numeric HTTP CONNECT, ADR 0161 reconnect FD smoke, ADR 0160 managed Core recovery.

## Decision

In the existing sixth real Daemon and fourth isolated read-only nonroot container on each native architecture, retain the approved Core PID, Applied=LKG and revision 2. Temporarily reject synthetic Selected SOCKS upstream connections. Rule and Direct HTTP CONNECT to numeric 127.0.0.1 must continue exact echo without touching the failed node. Selected must fail closed with empty EOF/reset or a fully framed, at most 1024-byte HTTP/1.0–1.1 4xx/5xx response. A premature HTTP 200 CONNECT acknowledgement is **not itself success**: it is tolerated **only when** a fixed bounded application probe receives zero application bytes and the tunnel closes with EOF/reset within the existing four-second socket bound; the synthetic Selected node must independently record an upstream rejection and zero accepted dials. Actual forwarded data, stalled 200 tunnel, other 2xx, redirect, partial/malformed response, timeout and route bypass remain hard failures. Require the Selected upstream rejection counter to advance with no accepted connection. Always restore the failure toggle, check same PID/generation, and verify fresh Rule/Direct/Selected HTTP CONNECT traffic, with exactly one new Selected successful upstream hop.

Add deterministic no-network tests covering the success/failure parser, explicit denial versus bypass, PID drift, Rule crossing and recovery bypass. The final lifetime Selected accepted count increases 52 to 53. Full native success adds T22_AIRGAP_HTTP_SELECTED_FAIL_CLOSED=ok. Preserve T22_HOSTNAME_AND_UDP_VERIFIED=false, T20_1000_RECONNECTS_VERIFIED=false, and T25_72H_7D_30D_SOAK_VERIFIED=false.

## Hard boundaries

No new Core, container, privileged port, external DNS or network, license, credential, TUN, or subscription/ISP routing layer. This is only local HTTP CONNECT Selected failure isolation, not domain/UDP/absolute-form, real CN five-layer SRS/28-group proof, full T22, 1000 reconnects, long soak, power loss, Restore/GC or release approval. Keep stable main and release Draft PR #1 unchanged.


## Native dual-arch CI failure localization

The first PR #40 exact stacked head `97dd0ed3` passed ordinary Python/Go, all four Go Race jobs and Managed Core integration, but its fourth native container failed on **both amd64 and arm64** with only the coarse `held-stop-explicit-restart` stage. The root cause is not established. Preserve fail-closed checks and the original 4-second per-socket bound; do not convert incomplete headers, an HTTP 200 by itself, or missing upstream rejection into success. The native harness now reports **only fixed, non-secret stage labels** for the sixth restart, SOCKS recheck, 72-connection FD smoke, three HTTP CONNECT tests, Selected rejection, its observed upstream counter and recovery. Only exact code-owned messages map to a fixed error code; unexpected errors remain `unclassified`. No failure details or potentially sensitive socket/runtime content are printed. New head must independently pass full ordinary CI, Race 4/4, integration and native dual architecture before merge.


## Verified behavior under native failure

The following exact-head native rerun `af799119` localized **both amd64 and arm64 failures** to `http-failure-selected-response` with `http-selected-unsafe-response`. The previous rejection check had conflated HTTP CONNECT **handshake status** with successful application routing. Some mixed HTTP proxy handlers acknowledge CONNECT with a 200 before the outbound SOCKS dial fails. This revision checks the semantic security property instead: a premature 200 must be followed by a bounded, zero-data EOF/reset after sending a fixed localhost-only application marker. The independent synthetic node rejection counter must still increment and its accepted connection count must remain unchanged, and all Rule/Direct/Selected recovery checks remain in force. It does not accept a mere 200, any application byte, a stalled socket, fallback or a missing upstream refusal. Negative tests cover payload leakage, timeout, other 2xx and malformed headers; all status codes and socket responses remain subject to exact-head native CI.
