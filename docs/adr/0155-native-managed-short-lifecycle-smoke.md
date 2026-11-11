# ADR 0155 — T25 preflight: bounded managed-Core lifecycle and Daemon FD budget

- **Status:** a short synthetic, **not** 72h/7d/30d soak or T25 release acceptance.
- **Depends on:** ADR 0149–0154: genuine Linux Daemon/Core managed generation, permitted native local Core, valid CAS promotion, Selected refusal, one pidfd-verified child crash and durable stopped state.
- **Scope:** existing **fourth** native amd64/arm64 `docker --network none` container, same UID 10001 with cap-drop/no-new-privileges, read-only rootfs, a fresh private SQLite; no new external network or provider resources, no TUN or subscription/ISP routing layer.

## Risk

A single startup, generation handoff and crash recovery is not sufficient evidence that repeated administrative **start/stop** requests leave no listeners, stale Core process, changing Applied/LKG generations or obvious resource leakage in a long-lived Daemon. T25's actual days-long soak is still unavailable, so this decision adds only a strictly bounded early warning without asserting 72h/7d/30d coverage.

## Decision

After ADR 0154's single Core-only crash, explicit stop and **fourth** clean Daemon open of the **same disposable SQLite**:

1. Open a **fifth** real Daemon on the same SQLite and verify the confirmed declaration head SHA, config/declaration revisions 2, Applied=LKG to the promoted generation and durable *stopped* intent. Do not auto-start a Core. Capture a positive/valid baseline count of the same-UID Daemon's `/proc/<daemon_pid>/fd`, not the Core's descriptors.
2. Execute exactly **three** explicit CLI `core start` → real data probes → `core stop` cycles, each with a bounded command timeout. Verify each running PID is the same-UID direct child with the approved executable; verify the same config revision, declaration revision, Applied/LKG and no recovery or pending operation, and test all three Rule/Direct/Selected SOCKS5 localhost echo payloads. The **middle** cycle also denies a single Selected upstream SOCKS5 CONNECT, checks Rule/Direct isolation and fail-closed Selected, clears the refusal and verifies healthy Selected restoration with the same Core PID.
3. After **every** explicit stop, require persisted stopped intent, PID=0 and no default Core listeners. Measure the Daemon's `/proc/<pid>/fd` count at this stopped/quiescent point. Reject missing/noninteger counts or a sample at/above 1024 descriptors. Bound all three samples to baseline+24 and to a max-min span of 16, identifying only **gross** monotonic or sudden FD growth.
4. Close that Daemon cleanly. Open the **same disposable SQLite** in a **sixth** Daemon and require the promoted Applied/LKG generation, declaration digest and *stopped* intent to persist with no Core listener or implicit restart.
5. Keep the preexisting native Core SHA/permission guards and three other independent `--network none` containers unchanged; append `T25_AIRGAP_SHORT_LIFECYCLE_SMOKE=ok` only after the entire deterministic experiment, and **always** print `T25_72H_7D_30D_SOAK_VERIFIED=false`.
6. Add no-network Python regressions for invalid FD baseline/samples, lifecycle state, three pairs of explicit commands, real per-cycle Core child identity, uniqueness of payloads, one Selected refusal, drift refusal, and no unexpected Core start.

## Not proven

Three short local cycles are **not** a statistically meaningful memory leak, throughput, user-load, DNS/GeoIP/GeoSite/ACL, remote node, reconnection-loss or long-term stability test, and FD slack is deliberately an early warning, not a production leak SLO. No real CN resource licenses, SRS offline distribution, complete signed tar installation, physical guest reboot/power outage, two-way rollback, credentials/HMAC restore, T15/T23/T24/T25 release approval, Restore/GC or any 72h/7d/30d result are implied. `core_distribution=false`, `cn_preset_offline_bundle=false`, 28 CN groups and five-layer routing untouched. `main` unchanged, outer PR #1 Draft.