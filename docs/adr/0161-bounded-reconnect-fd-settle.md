# ADR 0161 — bounded managed Core reconnect churn and FD settle (T20/T25 partial)

- **Status:** synthetic native network-none early stability preflight, **not** the full 1,000 reconnect T20 matrix, 72h/7d/30d T25 soak, an SLO, or release acceptance.
- **Depends on:** ADR 0149–0160, particularly the post-held-stop explicit same-generation restart, verified Rule/Direct/Selected SOCKS5 TCP paths, Core pinned child identity, and isolated localhost synthetic Selected node.
- **Envelope:** reuse **only the fourth existing** `docker --network none --cap-drop ALL --user 10001:10001 --read-only` container on each native amd64 and arm64. No new daemon/Core start, crash, port, external service, DNS, license, Core binary, privilege or TUN requirement.

## Gap

The three lifecycle start/stop cycles and short parallel-client smoke verify bounded transitions, but do not require *repeated* full SOCKS5 reconnects after a previously held-session stop and explicit restart. They also sample only Daemon FDs **when Core is stopped**, rather than validating both the still-running verified Core and its Daemon under repeated reconnect churn.

## Decision

1. Inside the sixth real Daemon session **after** the original explicit `core start` and the successful Selected refusal/recovery, retain the same pinned Core PID and Applied=LKG generation 2. Require current `/v1/status` (without mutation) and a direct same-UID approved Core child. Take read-only `/proc/<pid>/fd` baselines for both Daemon and owned Core; reject empty, noninteger and implausibly large samples.
2. Perform exactly **24** bounded cycles of three sequential full localhost SOCKS5 CONNECT + exact TCP echo + close paths (Rule 2080, Direct 2081, Selected 2082), **72 fresh connections** total. Each cycle must add *exactly one* synthetic Selected accept; Rule/Direct must never cross Selected, Selected refusals must not increase and the prior parallel test tags must not change. Recheck real PID/config/declaration revision 2 and Applied=LKG every eight cycles and after the last cycle. No hidden restart, compile, apply, DNS or external traffic is permitted.
3. With all probe connections closed, allow **at most four seconds** for the two procfs FD counts to settle. Require Daemon FD at most baseline + 16 and pinned Core FD at most baseline + 24, with all samples within (0,1024). This is a **gross bounded drift smoke guard**, not a proof of no leak or a throughput/latency SLA. If any status, route, echo or FD check fails, the already existing `finally` must explicitly stop Core and verify persisted stopped intent/PID=0/no proxy listeners.
4. Add no-network regression tests for exactly three inbounds per cycle, unchanged PID and one Selected hop per cycle, accepted bounded samples, invalid cycles/numeric FD values, unexpected Selected denial/bypass, stale or changed PID, and FD drift. Update final synthetic Selected total from 27 to **51**. Print `T20_AIRGAP_BOUNDED_RECONNECT_FD=ok` only on full native success and explicitly print `T20_1000_RECONNECTS_VERIFIED=false` plus `T25_72H_7D_30D_SOAK_VERIFIED=false`.
5. This does not replace the T20 **1,000** reconnect test under real load or the T25 72h/7d/30d trial, which require longer-duration memory/goroutine and routing/DNS state evidence. No new user API, service permission or release gate is enabled.

## Release and safety boundaries

T15/T23/T24/T25, full T20, CN 28 groups/five-layer SRS and resource licenses, real remote DNS/proxy, offline tar licensing, physical power loss, credential/backup restore, two rollback trials, long-term performance and authenticated releases remain OPEN. `core_distribution=false`, `cn_preset_offline_bundle=false`, Restore/GC disabled, no TUN and no subscription/ISP routing layer; stable `main` and outer Draft PR #1 unchanged.


## CI diagnosis for an earlier amd64 pre-reconnect failure

The first stacked PR #38 run passed ordinary CI, Race 4/4, integration and native arm64, but native amd64 failed with `T24_AIRGAP_FAILURE_PHASE=held-session-lifecycle`, **before** the new reconnect step. The underlying failure cause is not established; a cross-architecture pass does not excuse it. The lifecycle harness now reports fixed subphase labels for each of the three start/route/stop/port-audit steps, the parallel/refusal boundary, and the FD budget. Only fixed labels and exception **classes** reach the workflow; secret-bearing exception messages, daemon logs and user input do not. A unit regression verifies the complete expected phase sequence and rejects a non-callable diagnostic hook. There are **no additional retry attempts, widened timeouts, released assertions or success markers** as a result of this investigation. The next exact-head dual-arch CI must pass before merging.


### Strict fixed code for rejected test runs

Besides `T24_AIRGAP_FAILURE_PHASE` and exception-class output, rejected runs now emit `T24_AIRGAP_FAILURE_CODE`. Only an exact match against a small hardcoded set of *our own* RuntimeError messages is mapped to a fixed lowercase code; arbitrary exception messages, URL/token content, and errors of other classes emit only `unclassified`. The policy test checks known mappings and rejects accidental disclosure. This is telemetry for failed native smoke runs, not a pass condition, permission escalation or excuse to retry a failed gate.


## Follow-up: crash-recovery failure isolation (2026-10-26)

The PR-mode amd64 Core Provenance for former head `771f895` failed in a coarse `crash-recovery` phase with a sanitized `unclassified` RuntimeError, while an independent earlier push-mode dual-arch Core Provenance had passed. This inconsistency is **unresolved**; rerunning without a diagnosis is not proof of long-term stability. Only hardcoded subphase markers for crash start, initial routes/Selected refusal, all three held tunnel opens, PID identity check, existing **single** pidfd-supervised crash/recovery, old-socket EOF, node accounting, explicit stop, and the stopped-intent audit are now reported. Exact matching code-owned crash error strings may map to fixed public error codes, but all arbitrary error strings remain `unclassified`. No extra SIGKILL, retries, timers, permission changes, bypasses, weaker checks or altered resource thresholds. Exact-head CI and both architectures still gate the merge.


## Root cause candidate: configured does not mean stopped-ready

The initial `run_daemon` readiness loop previously accepted the first `core_configured=true` snapshot, then called staged-restart, crash-recovery and lifecycle callbacks that immediately required an already **stopped, zero-PID, no-operation** generation. These are not equivalent states. A fresh Daemon can expose a configured snapshot before it has completed stable stopped-state journal reconciliation. This is a concrete premature-readiness race in the **test harness**, plausibly consistent with intermittently failing native entry phases; no evidence yet proves it explains every observed failure.

The unchanged 20-second polling window now waits for `core_desired_state=stopped`, `core_state=stopped`, PID 0/null, `recovery_required=false`, a closed circuit and no active operation before executing any callback. An unexpected running intent or running Core **fails immediately**, not silently retries. Failed status CLI queries remain subject to the existing bounded readiness retry only. Deterministic no-network tests inject `configured=true` transitional status snapshots, verify the callback receives only a stable stopped state, and verify implicit running is refused with a fixed safe code. This does not alter production Daemon behavior, Core policy, timeout budgets, routing, process ownership or final native pass conditions. New exact-head native dual-architecture results are required.
