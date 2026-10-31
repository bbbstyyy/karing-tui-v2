# ADR 0160 — held SOCKS5 tunnels during a supervised Core crash

- **Status:** M5 / T25 early bounded native preflight; not the T25 72h/7d/30d gate.
- **Depends on:** ADR 0149–0159 and the currently approved native Linux Core with isolated local echo targets.
- **Envelope:** all work remains in the fourth existing read-only, nonroot, `--network none --cap-drop ALL --security-opt no-new-privileges` container on native amd64 and arm64. No TUN, privilege escalation, external IP/DNS, CN SRS package, licensed distribution or persistent user data.

## Motivation

ADR 0154 verified a single pidfd-owned Core crash and supervised new-PID recovery while ordinary application probes had already closed. ADR 0158/0159 verified deliberate operator stop of three established tunnels and clean explicit restart. Neither proves an **unexpected Core crash while three client TCP streams are established** also terminates the old streams without accidental fail-open or unbounded orphan sockets.

## Decision

1. In the existing third real Daemon run, before **the original single** pidfd-bound SIGKILL, establish three actual SOCKS5 TCP tunnels through Rule 2080, Direct 2081 and Selected 2082, each with a complete exact echo from the numeric 127.0.0.1 target; retain all three client sockets in an exception-safe `ExitStack`.
2. Check actual Daemon Core PID, config+declaration revision 2 and Applied=LKG generation before opening and again immediately after opening. Require exactly **one additional** Selected-node CONNECT and no Rule/Direct traffic through that node, with no new refusals. On an unhealthy node, changed generation or PID, **do not issue the crash**.
3. Invoke the unchanged verified `probe_supervised_crash_recovery`: it validates direct child/same UID/pinned executable, opens a pidfd, rechecks identity immediately before `pidfd_send_signal(SIGKILL)`, closes the pidfd in all cases and supervises one crash recovery to a fresh PID on the same Applied/LKG.
4. After fresh Rule/Direct/Selected probes, Selected-only refusal, and recovery on the new PID, demand **EOF/reset/abort on each of the three old client sockets** within the existing bounded timeout. A new healthy listener must never be mistaken for survival of an old tunnel. The context manager closes every socket even on a stale-PID refusal, failed recovery, timeout or unexpected old-stream traffic.
5. Add no-network unit regressions for three successfully held sockets and exactly one existing crash; stale or changed PID, invalid node and Rule crossing Selected must refuse crash. A failure to recover or to close an old stream must fail the experiment. Update the resulting synthetic Selected accepted count from 26 to **27**; the existing refusal lower bound remains unchanged. Emit `T25_AIRGAP_CRASH_HELD_SESSIONS_CLOSED=ok` only on full native success.

## Explicit non-claims

This is a controlled one-crash local functional experiment, **not** preservation of the three old sessions, zero-downtime switch, repeated crash storm, production throughput/latency SLA, actual CN 28-group and five-layer DNS/SRS, licensed offline tar, physical power loss, SQLite credential restoration, two rollbacks or 72h/7d/30d soak. No restore/GC or Core/ruleset distribution privileges are enabled; T15/T23/T24/T25 and M5 stable release remain OPEN. No TUN, no subscription/ISP routing layer, stable `main` unchanged.
