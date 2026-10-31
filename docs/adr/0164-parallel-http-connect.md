# ADR 0164 — bounded concurrent native HTTP CONNECT route isolation (T22 partial)

Status: bounded native network-none protocol smoke, **not** full T22 acceptance or a throughput benchmark.
Depends on: ADR 0162 numeric HTTP CONNECT on Rule/Direct/Selected, ADR 0163 Selected refusal and same-Core recovery.

## Gap

Prior real HTTP CONNECT tests are sequential. Under six simultaneous clients, mixed-inbound handling could incorrectly share a Selected upstream, cross-route Rule/Direct, or lose the association between a client payload and its approved selected node. Earlier ADR 0156 covers concurrent **SOCKS5**, but not HTTP CONNECT's distinct parser and tunnel path.

## Decision

- Reuse the **same sixth managed Daemon and pinned Approved Core PID** in the same existing fourth native linux amd64/arm64 `docker --network none --user 10001:10001 --cap-drop ALL --read-only` container, after ADR 0163's one Selected refusal/recovery. No new process, syscall privilege, DNS, destination, external traffic, license or TUN.
- Establish a barrier of **six simultaneously released clients**, 2 clients per Rule 2080 / Direct 2081 / Selected 2082. Each client performs **two sequential fresh HTTP/1.1 CONNECT** handshakes to the existing numeric ephemeral 127.0.0.1 echo, with exact binary application echo: 12 total HTTP tunnels. Use the existing 32-byte unique `parallel_probe_payload` tags, read in the synthetic Selected SOCKS node even if TCP packet boundaries split them.
- Demand **exactly four new Selected upstream CONNECTs**, zero new Selected refusals, no node failure, and exactly the four expected distinct Selected payload tags (no Rule/Direct tag). Check real Core PID, declaration/config revision 2 and Applied=LKG generation both before and after. Any failure of echo, HTTP status/framing, worker completion, tag uniqueness/route isolation or PID causes the existing explicit Core stop and final stopped-intent audit; no implicit routing fallback or retries.
- Add no-network negative tests for incorrect PID, invalid port, unhealthy node, Selected bypass, Rule crossing, compensated cross-route count, duplicate Selected tags, unexpected refusal, failed node, worker exceptions and mid-workload Core restart. Keep the existing 40-second outer futures bound, 8-second start barrier and per-socket 4-second limit.
- Final synthetic Selected accepted lifetime count increases **53 → 57**. Emit `T22_AIRGAP_PARALLEL_HTTP_CONNECT=ok` **only** on completed native smoke in both architectures. Preserve `T22_HOSTNAME_AND_UDP_VERIFIED=false`, `T20_1000_RECONNECTS_VERIFIED=false`, `T25_72H_7D_30D_SOAK_VERIFIED=false`.

## Non-claims and release holds

No HTTP absolute-form or hostname/DNS, UDP, auth, physical WAN, CN five-layer/28-group SRS assets, legal offline bundle, 1,000 TUI reconnects, physical power loss, long soak, Restore/GC or signed distribution proof. T15/T23/T24/T25 and full T20/T22 release gates remain OPEN. No TUN, subscription/ISP routing layer or changes to stable `main`.
