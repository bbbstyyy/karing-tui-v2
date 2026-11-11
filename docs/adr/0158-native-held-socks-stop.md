# ADR 0158 — T25 preflight: explicitly stopping Core closes held SOCKS5 sessions

**Status:** synthetic bounded T25 functional preflight. It is **not** a real service-upgrade/no-drop SLA, long soak, backup restore, or release acceptance.

**Preconditions:** ADR 0149–0157, including a real pinned native Linux Core managed by a genuine Daemon over a private SQLite, a persisted promoted Applied=LKG generation 2, three explicit start/stop cycles, independent local Rule/Direct/Selected SOCKS5 TCP forwarding, concurrent Selected failure and recovery. This is only the fourth of four independently isolated native amd64/arm64 `docker --network none` containers; UID 10001, read-only root, `--cap-drop ALL`, no-new-privileges. No external DNS, remote traffic, CN SRS, privileged TUN, or subscription/ISP routing layer.

## Gap

The prior short lifecycle smoke verified that each explicit `core stop` removes **listening** ports and persists stopped intent, but all test clients had disconnected by the time Core stopped. That does not prove a stop actually terminates **already-established TCP tunnels**. Surviving stale transport streams or a leaked Core child could retain resources and confuse subsequent explicit start/stop transactions even when listeners have disappeared.

## Decision

Within the **third** explicit Core lifecycle cycle of the existing fifth Daemon session, after ADR 0157's healthy parallel traffic → simultaneous Selected refusal → recovered healthy parallel traffic, while **the same PID**, declaration/config revision 2, Applied=LKG generation 2, and healthy running intent still hold:

1. Connect one **new live** synthetic SOCKS5 tunnel to each numeric loopback inbound: Rule 2080, Direct 2081 and Selected 2082. Perform the full SOCKS5 greeting, CONNECT for the single approved `127.0.0.1:<ephemeral echo port>`, send a distinct `held-stop-<port>` payload, require the exact echo and **retain all three client sockets open**. No third-party sockets or unapproved destinations. Failed handshakes and echo mismatches must close the socket immediately.
2. Require the synthetic Selected node's **successful** upstream connection count stays constant for Rule/Direct and increments **exactly once** for the held Selected stream; refuse a crossed route, Selected bypass, fixture failure or still-active refusal. Keep all clients open simultaneously using an exception-safe `ExitStack`.
3. While these three established client streams remain open, issue exactly **one deliberate** `core stop` CLI operation with a 20-second command bound, then poll genuine Daemon state for `stopped`. Each held socket must observe **EOF or connection reset/abort** under a 3-second read timeout; any post-stop bytes or silent hanging connection is a failure. Never reinterpret a read timeout as successful closure.
4. Always close all client descriptors even if stop, route accounting, status, or EOF assertions fail. After closing, keep the existing generation/LKG/stopped/PID=0 checks, no proxy listeners, Daemon stopped FD budget and final **sixth** Daemon open on the same disposable SQLite. It must retain **stopped** intent and approved applied generation without automatically starting another Core.
5. Add no-network stdlib regression cases for real greeting/CONNECT/echo framing, invalid port/target/payload, refusal/incorrect echo resource cleanup, closed/reset/aborted versus lingering/timeout sessions, incorrect Rule/Direct/Selected node-hop counts, failure-safe context cleanup, and precisely one CLI stop under three held connections.
6. Retain all old native test markers and append `T25_AIRGAP_HELD_SESSIONS_STOPPED=ok` only after native success in **both architectures**. Always keep `T25_72H_7D_30D_SOAK_VERIFIED=false`. Exact-head ordinary Go/Python/build/format, Race 4/4, Managed Core Integration, native amd64 and arm64 Core Provenance remain required before merge. Retarget after PR #34 itself merges.

## Boundaries

The test intentionally **breaks active test TCP sessions** on an explicit operator stop, not a no-drop graceful upgrade. Only three synthetic localhost streams are held; this is not load throughput/latency or sustained memory/FD soak, a real CN five-layer/28-preset route test, physical host reboot, remote proxy loss, authentic offline tar packaging, source-license authorization, credentials/HMAC restore or two rollback trials. Keep T15/T23/T24/T25 and M5 release gates **OPEN**, Restore/GC disabled, `core_distribution=false`, `cn_preset_offline_bundle=false`, stable `main` unchanged, outer PR #1 Draft.