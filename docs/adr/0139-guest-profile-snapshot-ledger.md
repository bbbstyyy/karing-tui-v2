# ADR 0139 — Bounded retained profile snapshot and node ledger in disposable guest audit

- **Status:** M4 guest-only, read-only cross-language T15/T23 subset; NOT real VM reboot, power loss, production restore, Core health or a release gate.
- **Depends on:** ADR 0138 and the real Go SQLite v18 M3 profile identity/snapshot contract (ADR 0054–0057).
- **Constraints:** Linux ordinary user, no TUN; preserve all 28 CN groups, Custom → GeoSite → GeoIP → ACL → FINAL, and exclude subscription/ISP routing.

## Problem

ADR 0138 pins declaration revisions and all retained generation BLOBs, but SQLite v18 also stores independently editable profile state, two retained snapshots per profile and the nodes belonging to each snapshot. A *previous* retained snapshot node's JSON and its matching stored SHA could be changed while current routing, Applied/LKG, declaration head, selection and every existing ledger remained identical. These payloads may contain private node parameters and must not appear in audit reports.

## Decision

1. Advance **disposable guest baseline v7 → v8** (production SQLite stays v18). Never silently reinterpret/overwrite previously independent SHA-pinned witness files; start a new owner-private guest/nonce.
2. In the existing WAL-aware **read-only SQLite transaction**, capture sorted `profile_state`, `profile_snapshots`, and `profile_snapshot_nodes` as a single ordered SHA-256 ledger. Enforce exactly current/previous retained snapshot ownership, valid profile IDs and source metadata, timezone-aware timestamps, correct profile-to-snapshot pointers, contiguous per-snapshot node ordinals, nonempty UTF-8-safe identities, valid bounded JSON and recomputed lowercase node-payload SHA. Hash source revision/source SHA *as stored*; do not falsely claim independent verification of a remote subscription's original bytes.
3. Guest-only hard budget: at most **64 profile-state rows, 128 retained snapshot rows, 8,192 node rows, 1 MiB per node JSON and 48 MiB aggregate node payload**. Iterate node rows rather than `fetchall`, fail closed on missing/orphaned refs, inconsistent row data, invalid JSON, SHA mismatch or exceeded budgets. The product's profile/snapshot limits are **not changed**; a larger otherwise valid live database is not admissible for this deliberately narrow disposable experiment.
4. Put only `profile_state_record_count`, `profile_snapshot_record_count`, `profile_snapshot_node_count` and `profile_snapshot_ledger_sha256` in the private baseline. Never emit node JSON, subscription URLs, profile IDs, node tags, names or timestamps in a user-facing report. Both strict `verify` and prepared-only `reconcile-verify` require this immutable ledger unchanged.
5. Python synthetic fixtures exercise valid previous/current snapshots, previous JSON replacement plus recomputed SHA, pointer/name drift, invalid JSON/ordinals/hash and resource-budget refusal. An independent Go cross-language test uses production `CommitProfileSnapshot` twice in a throwaway real SQLite v18 DB, pins the original read-only witness and then mutates/re-hashes *only the previous* retained node. The original Python verifier must reject. Before mutation, guest audit must not change SQLite main bytes.

## Exclusions and follow-up

`profile_sources` contains URL/fetch/update state, and `profile_node_overlays` contains user preferences; both are **outside** this snapshot-only ledger and require separate coverage. No archived/pruned third-or-older profile snapshot can be reconstructed. SQLite source SHA alone cannot authenticate missing remote source bytes. No Core traffic, external rule inode/resource closure, HMAC archive, credential-preserving restore, true guest VM stop/reboot, actual power loss or physical deletion was performed. All authorization flags remain false; T15/T23/T25, CN resource redistribution/license work and 72h/7d/30d soak remain OPEN. Stable `main` and Draft outer PR #1 are not release targets for this slice.
