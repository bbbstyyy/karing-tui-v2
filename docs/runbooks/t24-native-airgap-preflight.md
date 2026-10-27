# T24 native airgap preflight — ADR 0146/0147

**CI-only, disposable Linux native amd64/arm64, never a production installation guide.**

Use `.github/workflows/core-provenance.yml` to build and SHA-verify the approved Core, compile the management CLI and fetch the **digest-pinned** Python OCI image **on the connected CI runner**. The isolated container has no network (`--network none`), no Linux capabilities (`--cap-drop ALL`), no privilege escalation, ordinary UID 10001, read-only root+staged binaries and a private tmpfs for state. Never mount user settings, share host networking, enable TUN or grant root.

Two **distinct** container executions are required on **both** native architectures: `t24_airgap_bootstrap.py` opens real Daemon/SQLite and private Unix sockets twice, refusing unexpected Core activation and license-capability escalation; `t24_airgap_loopback_core.py` runs the approved standalone Core with a fixed local-only config, checks Clash API denial/identity and sends real SOCKS5 CONNECT messages through rule/direct/selected to a disposable TCP echo service bound solely to **127.0.0.1 inside the same namespace**, then requires clean SIGTERM. CI must print `T24_AIRGAP_NATIVE_BOOTSTRAP=ok` and `T24_AIRGAP_LOCAL_CORE_SOCKS5=ok` in both native jobs. Failures mean a manual hold, not a fallback to connected tests.

This is no claim that a package installs without internet, that CN rules/files are licensed, that DNS/remote nodes or the full five-layer routing policy work, or that Core is controlled by a production Daemon. The 67 unlicensed candidate CN assets, absent geoip:bing, full T24, T15/T23/T25, HMAC/credentials/rollback and long soak remain blocked.

## ADR 0148 — third native container: verified-Core cold refusal

The existing two containers remain required on **both** native architectures. A third distinct test container runs `scripts/offline_lab/t24_airgap_managed_cold_guard.py` under the same non-root/no-capabilities/no-network/readonly constraints. Its staged approved Core is root-owned **by the connected GitHub runner before isolation** so the production Daemon's strict artifact verifier accepts it; the script also recomputes the original per-arch locked SHA inside the test container. The actual `KARING_TUI_CORE_PATH` Daemon opens an isolated SQLite/Unix socket, creates an owner-only persistent Core control secret and must keep Core **stopped with no generation or TCP listeners**. One deliberate `core start` without a committed generation must fail; the script **explicitly runs `core stop`** to restore durable stopped intent before restarting the Daemon on the same test state. Symlink and fake-Core paths must fail startup without lingering sockets or secrets.

A successful log prints only `T24_AIRGAP_MANAGED_CORE_COLD_GUARD=ok`; the same run prints `T24_MANAGED_CORE_WITH_APPLIED_GENERATION_VERIFIED=false` and `T24_CN_OFFLINE_LICENSE_APPROVED=false`. No real user files, SRS, remote DNS, production Core apply, restore, power loss or release tar is tested. T15/T23/T24/T25 and licensing remain OPEN.

## ADR 0149 — fourth container: real Daemon-managed generation with synthetic local-only traffic

After the **three** previous independent native `docker --network none` checks, a **fourth** readonly, cap-drop ALL, UID 10001 container runs `scripts/offline_lab/t24_airgap_managed_applied.py` on **both native architectures**. Its only declaration contains a synthetic 127.0.0.1 SOCKS5 node and no licensed rules. The real daemon commits/compiles/applies that declaration over its Unix socket, then the test explicitly starts its approved Core child and sends SOCKS5 traffic from 2080/2081/2082 to a disposable loopback echo service; Selected must traverse the local fake SOCKS node. Explicit stop, Daemon restart on the same throwaway SQLite and a repeated local roundtrip are mandatory. Logs publish only `T24_AIRGAP_DAEMON_COMMITTED_CORE_LOOPBACK=ok`, and `T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false`/`T24_OFFLINE_DISTRIBUTION_OR_RESTORE_APPROVED=false`. Never replace synthetic local fixtures with production user credentials, public proxy servers or CN resources, and do not treat this as real physical VM power-cut or complete T24 acceptance.

## ADR 0150/0151 — per-entry route accounting and Selected-only failure

The fourth synthetic localhost container now separately counts selected-node hops for Rule/Direct/Selected on the initial and persisted Daemon starts. It also temporarily denies SOCKS5 CONNECT from the synthetic selected node **without shutting down the managed Core or disturbing Rule/Direct**, asserts Selected does not succeed or bypass the chosen outbound, checks the managed Core PID/generation remains stable, then restores the node and retests. The same healthy→refusal→recovered sequence occurs after the Daemon restart. Unit tests cover malformed successes, missing refusals, cross-routing, no outgoing dial during intentional refusal and cleanup of the test-only fault toggle. Successful final CI also prints `T24_AIRGAP_SELECTED_NODE_FAILURE_ISOLATED=ok` on both native architectures.

The test still has no CN SRS files, remote DNS or physical link interruption. Its upstream is a synthetic local SOCKS responder, not a real failing subscription. Four isolated containers and previously approved Core hashes remain required; full T24/restore/license/distribution and long-soak gates remain OPEN.

## ADR 0152 — staged declaration, stale apply CAS and applied-generation continuity

The fourth independent no-network container now holds a real running approved Core while using actual Daemon Unix API calls to (a) reject a TUN-contaminated synthetic V1 declaration with HTTP 400 and no revision change, (b) stage/compile an otherwise identical localhost-only revision 2 changing **only log level**, and (c) demand HTTP **409** from a deliberately stale `expected_config_revision=0` apply. It checks live PID, applied/LKG generation, config revision, running intent and local SOCKS5 echo before/after. After explicit stop and Daemon restart, the **same disposable SQLite** must retain declaration=2 while applied generation=1; it explicitly starts that generation and repeats the local data/failure tests. On native amd64 and arm64, the successful fourth script prints `T24_AIRGAP_STAGED_REVISION_CAS_ISOLATED=ok` together with prior markers.

Never interpret this as permission to discard or roll back a production generation. No candidate is activated on the stale path, and no CN SRS, credentials, remote DNS, public endpoint, archive restore or distributable package is involved. Continue manual hold for T15/T23/T24/T25, licensing, restore/GC and 72h/7d/30d.

## ADR 0153 — successful live managed-generation activation (synthetic only)

Retain all **four** independently isolated native amd64/arm64 no-network containers from ADR 0146–0152. The fourth container now completes the earlier staged revision 2 / stale CAS 409 experiment, explicitly restarts the Daemon on the same private SQLite while continuing to run Applied generation 1, and **then** applies the same verified synthetic declaration revision 2 with the correct expected config revision 1. The result must promote a distinct generation ID to Applied and LKG, start a different same-UID **approved pinned Core** process with running intent and no recovery, and preserve three-entry localhost SOCKS5 data-plane correctness plus Selected-node refusal/recovery. An explicit stop and **third** Daemon restart must preserve the new confirmed generation, keep Core stopped until a deliberate start, and pass the local forwarding and failure probe again before clean final shutdown. The successful fourth script prints `T24_AIRGAP_LIVE_GENERATION_HANDOFF=ok` as an additional bounded marker.

**Do not use this test as a release installation/upgrade procedure.** This deliberate Core restart is potentially disruptive and makes **no** zero-connection-loss promise. There is no production CN SRS, remote DNS, real subscription, third-party credentials, license clearance, offline tar artifact, physical reboot, doubly fault-injected rollback or long soak. Preserve the blocked T15/T23/T24/T25, Restore/GC and distribution gates.

## ADR 0154 — exact-child Core crash, bounded restart, durable stop (synthetic lab)

The fourth **existing** native amd64 and arm64 airgap container now additionally proves that a real Daemon-managed **promoted and persisted generation 2** survives one unexpected **Core-only** process exit. Verify the child is a matching pinned executable under the same nonroot UID and exact Daemon PPID; acquire a Linux pidfd and send SIGKILL through `pidfd_send_signal` only (refuse without pidfd). Watch real Unix status for a new PID, positive supervised failure count, unchanged Applied/LKG generation and revision 2, no circuit open or recovery-required flag, with bounded wait; re-run real local three-entry TCP and Selected SOCKS5 refusal/recovery. Explicitly stop, wait past initial backoff, check no listener, and open the same disposable SQLite in a fourth Daemon session to ensure stopped intent and generation 2 survived with no unrequested Core start. Success appends `T24_AIRGAP_PROMOTED_CRASH_RECOVERY=ok` on both native architectures. No extra container, network source, CN SRS or runtime ability is activated.

Do not execute this fault injection on a real user Core. It is **one controlled child crash**, not a failure-rate SLA, real host VM/power-off test, network-loss handling, authenticated archives/credentials, dual rollback, offline install tar or full T25 72h/7d/30d soak; T15/T23/T24/T25 and all distribution/recovery gates stay OPEN.

## ADR 0155 — bounded repeated Core lifecycle preflight, not T25 soak

The fourth existing native `--network none` container now uses a fifth clean Daemon open on the same throwaway SQLite after the promoted-generation crash/stop probe. It requires stopped intent, then performs **three** explicit managed-Core start→unique Rule/Direct/Selected localhost echo→stop cycles with stable declaration/config revision, Applied/LKG, direct-child binary identity and no lingering listeners. The middle cycle additionally checks Selected-node refusal and recovery. After each stop it samples only that Daemon's `/proc/<pid>/fd` count and rejects missing, implausible or grossly growing counts (baseline +24, sample span 16). A sixth Daemon open must find the persisted generation still stopped, no implicit Core process and the declaration SHA intact. A full success prints `T25_AIRGAP_SHORT_LIFECYCLE_SMOKE=ok` and **always** `T25_72H_7D_30D_SOAK_VERIFIED=false`.

These bounded synthetic loops do not provide a memory-leak SLO, throughput measurement, real network failure or 72h/7d/30d stability evidence. Keep all T15/T23/T24/T25, CN licensing, release/Restore/GC permissions and real power-failure verification OPEN.

## ADR 0156 — bounded parallel localhost Rule/Direct/Selected smoke

Within the fourth existing native amd64 and arm64 `docker --network none` container, the ADR 0155 fifth-Daemon/third-Core cycle additionally starts six test-only clients simultaneously behind a bounded barrier: two for each of the Rule/Direct/Selected SOCKS5 inbound ports, each sending two distinct echo payloads. All 12 localhost CONNECT/echo operations must complete under bounded client/future timeouts; the threaded synthetic Selected node uses a locked counter and must observe exactly **four** additional Selected requests **with exactly the four unique expected 32-byte Selected inbound payload tags** (bounded reconstruction across split TCP reads), zero new denials and no errors. The managed Core PID, Applied/LKG generation and revisions must remain constant after the burst; previous stopped-port, FD-count and restarted-Daemon safety checks continue unchanged. On exact native success, the test emits `T25_AIRGAP_PARALLEL_LOOPBACK=ok` in addition to prior partial markers; it still emits `T25_72H_7D_30D_SOAK_VERIFIED=false`.

The six-client localhost burst is **not** a throughput/latency SLO, a real user or network resilience exercise, actual CN distribution or a substitute for days-long T25 soak. No production release, Restore/GC, license, power-loss or dual-rollback gate is closed by this result.

## ADR 0157 — concurrent Selected upstream refusal with healthy Rule/Direct

Within the existing fourth native network-none T25 preflight, after ADR 0156's successful synchronized 12-echo test, a controlled **local Selected SOCKS5 upstream** refuses CONNECT while six clients simultaneously perform 12 bounded operations. Both Rule and Direct must complete all eight distinct local echo requests; each Selected client must observe SOCKS failure/close, never a success or direct fallback. Selected's successful relay and 32-byte payload tag counts must not increase; its refused CONNECT count must grow by **4–16**, and the refusal switch must always reset (even if the test fails). Recheck the same running approved Core PID/Applied=LKG config generation 2 and **repeat the entire 12-echo parallel healthy batch** before existing stop/FD/SQLite persistence checks. A successful native test adds `T25_AIRGAP_PARALLEL_REFUSAL_ISOLATED=ok`; it always reports `T25_72H_7D_30D_SOAK_VERIFIED=false`. This is synthetic TCP application refusal, **not** a remote outage, user-load soak, live CN routing/GeoIP, complete offline tar install, real power cycle, dual rollback, or production release approval.

## ADR 0158 — operator stop with three still-established SOCKS5 tunnels

In the existing fourth independent native linux amd64/arm64 `--network none` test, after healthy→Selected-failed→healthy concurrent route checks, open one real SOCKS5 echo session per inbound (Rule 2080, Direct 2081, Selected 2082), verify their initial echoes and **keep all three TCP sockets open**. The one Selected node must see one additional successful relay but no Rule/Direct hop. With all three sessions still held, call the real management CLI to stop Core, then require **each** old session to reach EOF or reset/abort within 3 seconds; a timeout or further received data fails the experiment. All held sessions are closed even if an earlier step fails. The existing PID=0, no listening ports, retained Applied/LKG, Daemon FD sampling and final disposable-SQLite stopped-intent checks remain. Native success adds `T25_AIRGAP_HELD_SESSIONS_STOPPED=ok` while retaining `T25_72H_7D_30D_SOAK_VERIFIED=false`. This is intentionally a disruptive stop, not zero-drop hot replacement, external outage testing, full CN SRS, offline redistribution, real power loss, dual rollback or actual T25 soak.

## ADR 0159 — operator restart after old TCP sessions were stopped

After the ADR 0158 native fourth-container experiment deliberately stops Core with three live Rule/Direct/Selected SOCKS5 test sessions and verifies they close, the **sixth** real Daemon on the same disposable SQLite must still start in stopped state with the same declaration SHA, revision 2, Applied=LKG promoted generation, no recovery and no listeners. Only after these checks should the test explicitly start Core, verify the new approved same-UID child PID, send fresh three-inbound numeric-localhost echoes, inject one synthetic Selected upstream SOCKS5 refusal (Rule/Direct must remain healthy, Selected must fail closed), and verify Selected recovers without Core PID change. The fixture explicitly stops Core in `finally` after a successful start, including on traffic failures, and demands PID=0/no listeners; a **seventh** Daemon open must find stopped intent with the same persisted applied generation and declaration SHA. Total synthetic Selected successful hops must be 26 and denied attempts at least 11. A complete native pass adds `T25_AIRGAP_HELD_STOP_RESTART=ok`, and always retains `T25_72H_7D_30D_SOAK_VERIFIED=false`.

This is a bounded deliberate operator restart, **not** zero-connection-loss, real external network loss, CN rule/credential distribution, VM power interruption, actual offline tar installation, durable rollback/restore, or 72h/7d/30d soak. All formal release and T15/T23/T24/T25 gates remain OPEN.


### ADR 0159: synthetic peer-close regression and bounded native diagnostics

- The test node treats only TCP reset/abort/broken-pipe **after a successfully forwarded application reply** as an expected session teardown. Pre-echo resets, protocol violations, other socket errors and timeouts remain hard failures; a client still must independently validate the entire exact echo and the three old held tunnels must report EOF/reset after stop.
- On native failure, use the fixed `T24_AIRGAP_FAILURE_PHASE` and `T24_AIRGAP_FAILURE_CLASS` labels to distinguish the final stopped-status, listener, Selected accounting or Core-hash gates. Do not print private Daemon logs, arbitrary exception strings, secrets, or network configuration to CI output.
- A pass on one architecture or a subsequent rerun is not evidence of long soak or complete T24/T25 acceptance; both native architectures and the ordinary CI gates must pass for the same PR head.

### ADR 0160: verify old sessions close on one supervised Core crash

The fourth independent network-none native Core smoke on each architecture must reuse the **existing single** pidfd-bound Core SIGKILL. While three completed localhost SOCKS5 echo tunnels remain open, require the exact same Daemon PID/generation/LKG before fault injection, then require all three old sockets to reach EOF/reset within the bounded checks. Only new connections through the restarted approved Core may succeed. The synthetic Selected node is required exactly once for the held triplet, with Rule/Direct isolated.

A failure before the crash must not signal any process; any failure closes all opened test sockets. Full native success adds `T25_AIRGAP_CRASH_HELD_SESSIONS_CLOSED=ok`. This is not zero-drop TCP, long-run soak, CN routing, actual host power loss, credential restore or permission to release distributable offline assets.


### ADR 0161: bounded 72-stream reconnect and procfs FD settle

In the sixth real Daemon after explicit Core start and Selected failure/recovery, perform 24 rounds of three complete numeric localhost SOCKS5 echo reconnects, closing each stream before the next. Verify exactly 24 additional Selected hops, no new denial or changed parallel payload tags, and unchanged real Daemon Core PID/Applied=LKG every eight rounds. Read only the pinned same-UID child Core and Daemon `/proc/<pid>/fd` baselines and final values. Allow no more than four seconds for Daemon ≤ baseline+16 and Core ≤ baseline+24; never accept empty/invalid or ≥1024 values. The existing unconditional explicit-stop cleanup must still run on failure.

A successful native amd64 **and** arm64 Core provenance run prints `T20_AIRGAP_BOUNDED_RECONNECT_FD=ok`, `T20_1000_RECONNECTS_VERIFIED=false`, and `T25_72H_7D_30D_SOAK_VERIFIED=false`. This early smoke is not the 1,000 reconnect or long soak performance/resource/SLA experiment, nor a CN licensed offline, remote DNS, physical power loss, rollback or production restore claim.



### ADR 0161 amd64 lifecycle failure isolation

One pre-rebase linux-amd64 native fourth-container run failed at the coarse `held-session-lifecycle` phase (before ADR 0161 reconnects); arm64 native and ordinary checks passed. The rerun must use the **new exact-head commit** after rebasing ADR 0161 onto merged ADR 0160. The test now records only hardcoded `held-lifecycle-preflight`, `held-lifecycle-cycle-{0,1,2}-{start,routes,stop,stopped-audit}`, `held-lifecycle-cycle-1-selected-refusal`, `held-lifecycle-cycle-2-parallel`, and `held-lifecycle-fd-budget` as sanitized CI failure phases. These are fail-closed diagnosis checkpoints, not retries, timeouts or skipped checks. Preserve failure status and investigate any recurring phase before merge.


On failure the native harness may now additionally print `T24_AIRGAP_FAILURE_CODE` from a strict fixed whitelist (e.g. `daemon-fd-drift`, `held-stream-not-closed`); `unclassified` is the safe fallback. Do **not** copy or forward temporary Daemon logs, exception messages, private network addresses or tokens into CI output. Keep the exact-head CI failure status until the issue is resolved.


Native-readiness correction: `core_configured=true` is not sufficient to call a restart/lifecycle callback. The preexisting bounded 20-second Daemon startup poll must first observe *durable stopped intent* and *actual stopped state* with PID 0/null, no pending operation, recovery requirement or circuit breaker. An unexpected running/auto-started Core aborts immediately. Ordinary transitional snapshots continue within the **same** readiness deadline; this does not waive a failed route, echo or FD check, nor change the release gates. A Python regression verifies transient configured snapshots cannot reach the callback.

### ADR 0162: bounded numeric HTTP CONNECT on the existing mixed inbounds

In the same sixth Daemon network-none run after ADR 0161 reconnects, send exactly one HTTP/1.1 CONNECT `127.0.0.1:<ephemeral echo port>` request through each Rule:2080, Direct:2081 and Selected:2082 mixed inbound. Require at most 1,024 bytes of a full HTTP/1.x 200 response header, followed by exact numeric localhost echo bytes; only Selected may increment the local synthetic upstream accepted count. Before and after these three requests, verify the same real pinned Core PID and Applied=LKG generation. Do not add HTTP credentials, external DNS/URLs, hostnames or system proxy changes. On any failure, the existing unconditional explicit stop and stopped-intent audit apply.

Only a fully passing exact-head amd64 **and** arm64 native run may print `T22_AIRGAP_HTTP_CONNECT_IP=ok`; always retain `T22_HOSTNAME_AND_UDP_VERIFIED=false`. This is neither full T22 support nor CN-rules/offline-release/power-loss/long-soak acceptance.


### ADR 0163: Selected HTTP CONNECT refusal and same-Core recovery

Temporarily enable only the local synthetic Selected node's reject flag after the ADR 0162 three-inbound HTTP success. Require separate Rule/Direct HTTP CONNECT exact echo with no Selected node activity. Selected HTTP CONNECT must close without data/reset or return a complete bounded HTTP 4xx/5xx header. Some mixed inbounds acknowledge CONNECT 200 before outbound refusal: a 200 alone never passes; send one bounded fixed local payload and require zero returned application bytes and EOF/reset within the original four seconds, plus an independently observed rejected Selected upstream dial and zero accepted dials. Any forwarded byte, stalled 200, other 2xx, redirect, malformed/partial header or timeout is a hard failure. Require an observed upstream rejection. Always restore the node flag, preserve the pinned approved Core PID and Applied/LKG, and repeat three-inbound HTTP CONNECT exact echo with one recovered Selected hop. Final accepted count is 53.

Native pass adds T22_AIRGAP_HTTP_SELECTED_FAIL_CLOSED=ok only. Never misreport hostname/UDP, real CN routes/DNS, 1000 reconnects, long soak or restore/release approval.


ADR 0163 CI diagnostic: a failed native run may expose fixed `http-restart-*` and `http-failure-*` labels plus the allowlisted `T24_AIRGAP_FAILURE_CODE`. These are emitted only on failure to locate the offending phase, never the exception text, Daemon log, endpoints or tokens. Do not weaken the HTTP Selected failure acceptance criteria, add retries or increase network/DNS privileges to make a red run green. Any new head requires complete amd64/arm64 native provenance and ordinary/Go Race/integration checks before merge.

### ADR 0164: simultaneous HTTP CONNECT mixed-inbound audit

After the Selected HTTP refusal/recovery step, keep the same sixth Daemon and approved Core and barrier-release six HTTP CONNECT clients (two per Rule/Direct/Selected). Each completes two numeric-localhost HTTP/1.1 CONNECT requests and exact 32-byte payload echoes; the Selected synthetic node must observe exactly four new accepts and **four distinct, expected Selected-only payload tags** even when TCP fragments bytes. Reject any Rule/Direct Selected traversal, compensated route swap, duplicate tag, new rejection or changed Core PID/Applied=LKG. The original concurrent barrier/future/per-socket time limits and explicit Core stop are unchanged. Final Selected accepted count becomes 57.

Only a passing exact-head native run can print `T22_AIRGAP_PARALLEL_HTTP_CONNECT=ok`. This is short bounded concurrency, not 1,000 reconnects, hostname DNS, UDP, CN resource licensing, restore or long soak.


### ADR 0165: concurrent Selected HTTP CONNECT failure and recovery

After ADR 0164's 12 successful barrier-started HTTP CONNECT echoes, enable only the synthetic Selected SOCKS node's refusal flag and run six clients / 12 fresh HTTP requests (two per Rule, Direct, Selected). Rule/Direct must complete eight exact local echoes with **no** Selected upstream activity; Selected must fail closed for four requests with bounded zero-data EOF/reset (an early HTTP CONNECT 200 is not enough) and trigger 4–16 synthetic upstream rejection observations. Require unchanged Selected accepted count/tags and same approved Core PID/Applied=LKG. Reset the flag unconditionally, then repeat 12 successful HTTP CONNECTs and verify precisely four new unique Selected tags. Final accepted lifetime count is 61; do not infer throughput, real WAN DNS, CN licensed rules or long-term soak from this smoke.

The marker `T22_AIRGAP_PARALLEL_HTTP_SELECTED_REFUSAL=ok` is legal only on full dual-architecture native success. Keep T20/T22/T24/T25 and all Restore/GC/official release gates OPEN.


### ADR 0166: established HTTP CONNECT tunnels close on the existing Core stop

After ADR 0165's concurrent HTTP Selected failure and same-Core recovery, use the sixth real Daemon to establish three **held** HTTP CONNECT localhost exact-echo tunnels, one per Rule/Direct/Selected mixed inbound. Do not close their client sockets before the pre-existing explicit `core stop`. Require exactly one Selected local upstream accept, no new refusals and unchanged approved Core PID/Applied=LKG. Once stopped, audit stopped intent/PID=0, no proxy listeners, and each old HTTP socket EOF/reset/abort within three seconds; continued application data or timeout fails CI. The inner `finally` must close all client sockets on every path. This is the same stop, not another lifecycle transition, crash or network operation.

On real native amd64+arm64 full success only, print `T22_AIRGAP_HELD_HTTP_STOP_CLOSED=ok`; keep T20 1000 reconnect, T22 hostname/UDP and T25 long soak as **unverified**, as well as CN licensed resources, recovery/rollback, Restore/GC and release.

### ADR 0167: six held SOCKS5 + HTTP tunnels under the existing pidfd-supervised Core crash

During the **same one** verified pidfd SIGKILL used by ADR 0160, retain three previously established SOCKS5 streams and additionally open and retain three fully acknowledged, locally echoed numeric HTTP CONNECT streams, one per mixed inbound. Before signalling, verify the approved same Core PID, Applied=LKG and only two Selected upstream successes across the six sessions. After the *existing* Core restart/recovery checks, demand EOF/reset for all **six** old tunnels within three seconds; no old connection may continue forwarding. ExitStack closes every held client socket even on a failed HTTP open, wrong PID, refused signal or EOF assertion. Final Selected accepted count becomes 63.

The marker `T22_AIRGAP_HELD_HTTP_CRASH_CLOSED=ok` requires complete dual-architecture native success. This is a bounded single Core crash only, not T15/T23 physical restoration, long soak, remote DNS, licensed CN resources or release approval.



ADR 0167 post-crash ledger follow-up: native `post-crash-stop` audits require **exactly 13** lifetime successful synthetic Selected upstream connections after the single supervised crash (the prior SOCKS-only **12** plus one held HTTP Selected tunnel), at least five observed Selected refusals, zero active reject toggle and no node fault. Do not accept 12, 14 or a noninteger counter. This check runs **before** later lifecycle workloads, whose final total remains exactly 63. Fixed error code `crash-post-stop-selected-accounting` is public-safe; never print raw exception strings or internal Daemon logs. No extra kill or weakened EOF assertion.

### ADR 0168: bounded split-write HTTP CONNECT request header

Before ADR 0166's existing held-HTTP explicit stop, send each numeric localhost HTTP CONNECT request as six ordered client `sendall` calls via Rule/Direct/Selected, splitting the method, Host and CRLF boundaries. Require complete ≤1024-byte HTTP 200 response and exact localhost echo, approved unchanged Core PID/Applied=LKG, exactly one extra Selected accept and no Rule/Direct Selected crossings or new refusals. The kernel may coalesce writes; do **not** describe this as verified TCP packet segmentation. Final selected accepted lifetime count is 64; the marker is `T22_AIRGAP_HTTP_SPLIT_WRITE_HEADERS=ok` only on complete dual-arch native success. This does not establish HTTP absolute-form, hostname DNS, UDP, real CN resources, T20/T25 endurance or release readiness.

### ADR 0169: absolute-form HTTP GET on three managed mixed inbounds

On the sixth approved Daemon and same running Core, add one test-only numeric 127.0.0.1 HTTP Origin in the existing no-network nonroot container. After the split-write CONNECT smoke and before the existing held-HTTP stop, submit three distinct `GET http://127.0.0.1:<origin-port>/t24-http-absolute-<inbound>` requests (Rule, Direct, Selected). The origin accepts only those paths in **origin-form** with the exact numeric Host and sends a deterministic bounded 200/Content-Length response. Independently audit three origin receipts and exact response bodies; require only one extra synthetic Selected upstream accept, unchanged refusal count, Core PID, declaration/config revisions and Applied=LKG. A wrong or missing Origin, unknown node destination, malformed/partial/oversized HTTP, unexpected routing or replaced PID fails CI. Unconditionally terminate the local origin thread/server on all paths.

Total lifetime synthetic Selected successful accepts becomes **65**; `T22_AIRGAP_HTTP_ABSOLUTE_FORM_IP=ok` is valid only after *both* native architectures fully pass. This does not grant hostname/DNS/UDP, TLS/remote production nodes, CN five-layer licensed resources, T20 1,000 reconnects, T25 soak, T15/T23/Restore/GC or release readiness.
