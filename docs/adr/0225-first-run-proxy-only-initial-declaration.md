# ADR 0225: explicit first-run declaration from an accepted source

Status: **implementation candidate / Pre-MVP**, not MVP or CN acceptance.

## Problem

The existing snapshot-to-declaration preview and stage operation requires a
positive base declaration revision. The real-Core MVP-1C HTTP subscription
fixture therefore wrote a synthetic declaration into SQLite first, even
though an empty Linux installation has no V1 declaration.

## First-run protocol

An already accepted and enabled profile source has an immutable snapshot and
stable NodeIDs. A user can call the protected local Daemon API:

1. `POST /v1/profiles/{profile_id}/declaration/initial/preview` with the
   accepted `snapshot_id`, a selected stable `selected_node_id` and
   **explicit IP:port** `resolver_address` (no embedded URI, credentials or
   default resolver). Returns source revision, effective node count, selected
   NodeID, overlay SHA-256 and canonical candidate SHA-256. It does **not**
   modify a declaration, run Core Check or apply a generation.
2. `POST /v1/profiles/{profile_id}/declaration/initial/stage` requires the
   exact preview candidate/overlay digests, source revision, snapshot/selection
   and resolver, plus `acknowledge_proxy_only_no_cn=true`. The candidate is
   rematerialized; SQLite atomically checks accepted source revision/snapshot,
   the current overlay revisions, empty declaration revision zero, no committed
   applied or last-known-good generation, no recovery flag and no active
   apply attempt before inserting declaration revision one.
3. Existing `GET /v1/config/apply/preview` and
   `POST /v1/config/apply/confirm` are still separate user actions.
   Native compilation, Core Check, activate, verify and durable readback
   remain mandatory; stage never triggers them.

Both responses state `routing_mode="proxy-only-no-cn"` and
`cn_rules_ready=false`. There are **no CN groups or licensed rule resources**
at this stage. It is an explicitly accepted technical-preview starting
state, not a substitute for the 28 Karing CN groups.

## Semantics and safety

The constructor uses only nodes actually materialized from the accepted
snapshot with overlays. It creates a CurrentSelected membership list and
sets FINAL to CurrentSelected, **not DIRECT**. No profile subscription/ISP
routing is imported. Direct remains a separate explicitly named inbound,
while Rule/Selected do not silently fall back to Direct.

The operator-supplied IP resolver is bound to the outbound and fallback DNS
roles. This does not validate real CN split DNS policy, privacy requirements
or offline resolver availability: those remain MV-03/MV-04 blockers.
Malformed, non-IP, multicast, unspecified, zero-port or absent resolvers
fail closed. No external resource or default resolver is downloaded.

The helper deliberately exposes no candidate document, node labels, raw
source, source location or secrets through public API success/error
responses. A timeout/disconnect after stage is an uncertain outcome: do not
retry blindly; read current declaration state. Preview is non-mutating and
the initial stage cannot overwrite an existing declaration or LKG.

## Evidence

- Pure constructor tests cover deterministic output, explicit selected target,
  actual credential materialization in the **internal** declaration, absence
  of CN/implicit Direct policy, and invalid/mismatched DNS/nodes.
- Daemon API tests cover empty state, safe preview, explicit acknowledgement,
  wrong hashes, stale source/snapshot/overlay/selection/resolver and replay.
- The real-Core HTTP subscription fixture starts with the new public first-run
  preview/stage before checked apply and local SOCKS5/HTTP CONNECT traffic.
- Exact-final-commit CI, managed Core and provenance evidence are required
  before merging; creation of this ADR does not count as passing evidence.

Remaining: user-facing CLI/TUI first-run workflow; full CN 28-group
semantics/licensed rule-set closure; supported common subscription formats
and Shadowsocks/VLESS/Trojan real transport verification; real restoration,
72-hour soak and dual-architecture delivery. Linux ordinary UID, no TUN,
no subscription/ISP routing and fail-closed behavior remain unchanged.
