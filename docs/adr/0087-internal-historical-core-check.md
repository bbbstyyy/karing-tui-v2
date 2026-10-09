# ADR 0087: Internal gated historical core-check without activation

- Status: M4 prerequisite implemented, **operator restore remains disabled**.
- Depends on: ADR 0084 historical audit; ADR 0085 selector/policy checks; ADR 0086 atomic historical candidate preparation.
- Scope: Linux unprivileged proxy only, no TUN or subscription/ISP routing layer.

## Motivation

The SHA-256 of an archived native core config proves only historical storage integrity. A daemon upgrade, changed control secret/port, selector intent, outdated rule files or a different compiler can make the archived native JSON unusable. More importantly, a successful `core Check` by itself is not permission to switch the running proxy.

## Internal dry-run

`serverRuntime.CheckHistoricalGeneration` is **not reachable from HTTP/CLI/TUI**, is not advertised as a capability, and is used as a deliberately non-activating prerequisite:

1. Hold the same daemon `OperationGate` as current-declaration apply, core lifecycle and selector mutation.
2. Run the bounded read-only generation audit, requiring the requested non-current committed generation to have retained verified payloads/resources and `bound_state_consistent_only` compatibility. Reject truncated history that does not contain the requested generation.
3. Check both applied and last-known-good generations' retained native/manifest/declaration integrity, selector compatibility and local rule-set closure; reject a missing fallback.
4. Strictly recompile the **historical declaration revision with today's configured compiler**, outbound selector intent, core control secret, ports, DNS and pinned schema. Require byte-for-byte agreement with the stored native config, serialized manifest and source-map. An old stored native config is never handed straight to the core on digest evidence alone.
5. Atomically prepare a new candidate generation through the v17 storage CAS and journal (ADR 0086), checking every mutable binding. Fail closed on stale selection/declaration/config/route-mode/LKG state or disk quota.
6. Invoke `core.Check` **only**, then repeat the binding/resource checks. All paths (successful check, rejected compiler, canceled operation, core-check error, observed drift) return without `Activate` or `Verify`, and the prepared journal slot is aborted via a bounded, cancellation-independent cleanup operation. Cleanup failure is itself a hard error.

The evidence object has `CoreChecked` but always `Applied=false` and `RestoreReady=false`. It is not persisted as an authorization or exposed to clients. No current confirmed generation, running core binding or desired state is changed. A check does temporarily stage an immutable private candidate file and creates an aborted journal entry, subsequently covered by existing retention policy.

## Remaining release gates

This is not an exact pinned filesystem-resource lease: rule file hashing before/after Check does not eliminate inode replacement between the two reads. Nor does the dry-run prove that the old routing + DNS graph remains healthy under live traffic. A future actual restore requires pinned immutable resources (including rollback-of-rollback dependencies), an explicit operator receipt bound to the audit state, safe core binary/adapter compatibility, a journaled `Check → Activate → Verify → Commit` transition, live selector/mode readback, bounded failure recovery, and interruption/fault injection at every boundary. The code must be audited for crash and storage-quota behavior before an operator endpoint is created.

All `GET /v1/config/recovery/audit` entries still report `restore_ready=false`, the top-level response remains `restore_supported=false`, and no new manual restore route or command is added. CN preset, five-layer routing and DNS behavior are unchanged.
