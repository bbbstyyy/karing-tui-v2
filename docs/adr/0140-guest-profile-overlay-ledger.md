# ADR 0140 — Complete bounded node user-overlay ledger in disposable guest replay

- **Status:** M4 Linux ordinary-user *guest-only*, read-only, non-authorizing T15/T23 SQLite subset.
- **Depends on:** ADR 0139 (v8 retained Profile snapshots), v18 `profile_node_overlays` and Go `CommitProfileNodeOverlay` CAS semantics.
- **Product constraints:** no TUN, retain CN's 28 preset groups, Custom → GeoSite → GeoIP → ACL → FINAL, never import subscription/ISP diversion into runtime routing.

## Missing evidence

ADR 0139 records the current/previous snapshot BLOBs, but **user node overrides are not stored inside those snapshots**. A disabled/favorite flag, alias or sort priority can change in `profile_node_overlays` without changing snapshot payloads, Applied/LKG, routing declarations, active selection or the prior witness. More importantly, an overlay for a node **removed from the current snapshot is deliberately retained** by the Go Store and can still matter if the source key returns. Requiring all overlays to reference a current node would silently drop legitimate historical user intent.

## Decision

1. Advance only the **disposable guest baseline v8 → v9**; production SQLite remains **v18**. Never overwrite/reinterpret previous independently pinned baselines; use a newly provisioned owner-private guest and nonce.
2. Under the existing single WAL-aware SQLite **read-only transaction**, inspect **all** `profile_node_overlays` in strict `profile_id,node_id` order. Check Go-compatible nonempty stable IDs (UTF-8, byte length ≤512, no controls/outer whitespace), positive revision, exact integer disabled/favorite in {0,1}, alias UTF-8 length ≤512 without controls/outer whitespace, nullable sort rank in [0, 2^62−1], and bounded timezone-aware `updated_at`. **Do not** reject legitimate dormant overlays just because current or previous snapshots do not contain their node IDs.
3. Enforce **2,048 total overlay rows** as the *guest-only* limit. This is separate from and intentionally narrower than the production limit of 8,192 overlays **per profile**; exceeding the guest experiment bound refuses without changing production behavior.
4. Hash every field in deterministic ordered JSON records with an explicit v9 ledger domain separator. The private guest witness receives **only** `profile_overlay_record_count` and `profile_overlay_ledger_sha256`; user aliases, node/profile IDs, timestamps and flags never appear as plaintext in the witness or report. Both strict `verify` and narrowly permitted `reconcile-verify` require exact pre/post equality of this ledger.
5. Python synthetic tests prove an unchanged empty ledger, matching two valid overlays (including a dormant one), drift of a detached alias/disabled/favorite without CAS revision advancement, malformed revision/flags/alias/rank/timestamp, the 2,049th-row refusal, and refusal of overlay drift during the otherwise-allowed prepared → interrupted reconciliation. A Linux Go test creates snapshots and overlays using **real v18** `CommitProfileSnapshot` and `CommitProfileNodeOverlay`, retains the removed-node overlay after refresh, pins a baseline via the original Python reader and verifies its refusal when only that dormant row is modified. Before tampering, the guest audit must leave main SQLite bytes unchanged.

## Explicitly out of scope

`profile_sources` still contains independently persisted fetch URLs, enabled/config state, update leases and subscription usage; it is **not covered** by this overlay ledger. Already-pruned snapshots are not reconstructed. No real VM cut/reboot, electrical power loss, external source authentication, Core route/DNS traffic, archive HMAC, credential restoration, resource GC or metadata deletion is performed. Every restoration/deletion flag remains false; T15/T23/T25, CN offline resource/license closure and long-soak remain OPEN. Outer PR #1 stays Draft and stable `main` is untouched.
