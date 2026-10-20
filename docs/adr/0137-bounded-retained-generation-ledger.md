# ADR 0137 — Complete bounded retained-generation ledger in disposable guest audit

- **Status:** M4, isolated/read-only regression only. Neither T15 nor T23 is accepted; no actual VM power cut/reboot, Core activation/health verification, restore, archive HMAC, credential import, or metadata deletion is performed.
- **Depends on:** ADR 0130–0136, real Go v18 Store `generations` and retention policy, Python guest witness reader with strict external baseline SHA.
- **Unchanged operating constraints:** ordinary Linux user, no TUN, CN 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL (subscription/ISP route layer excluded).

## Why

Existing read-only guest comparison digests (a) Applied and LKG, (b) the most recent pending apply candidate, and (c) full *apply_history metadata*. A retained generation that is no longer Applied/LKG or the latest pending candidate may survive the Go Store's 5-confirmed-generation retention window. Changing that historical `generations.config_json` and its *matching, recalculated* `config_sha256` previously leaves the above audit fields unchanged; the archived journal records keep their original digest, but there was no comparison against that older generation's live BLOB.

## Decision

1. Advance the disposable guest witness document **v5 → v6**. Never silently reinterpret a pinned older witness; start a fresh private guest experiment/nonce instead. Application SQLite schema stays real **v18**, unchanged.
2. During the existing single WAL-aware SQLite read transaction, read every retained `generations` row in increasing ID order, hard-limited to **128 rows** (request 129, then refuse). This is a deliberately small *guest experiment inspection budget*, not a replacement for Go's production retention policy or SQL quota.
3. For each row, require strictly increasing positive ID, nonnegative base revision, `target_revision=base_revision+1`, a nonempty valid JSON config BLOB (max 64 MiB), matching lowercase SHA-256, optional manifest/source-map JSON+digest **both absent or both present** (each max 16 MiB, hash-verified and valid JSON), and bounded timezone-aware `created_at`. Malformed or corrupt historic data fails **even before** the new witness can be captured.
4. Hash a fixed canonical ordered representation of **all** remaining generation identities, revisions, BLOB hashes/lengths and creation times. Add only `generation_record_count` and `generation_ledger_sha256` to the private v6 baseline. No config payloads, node secrets, file paths, rule text or timestamps appear in user-facing reports. Both strict `verify` and limited prepared→interrupted `reconcile-verify` pin this ledger because they compare the complete state.
5. Python synthetic negative tests prove a previously unreferenced generation with *self-consistent rehashed config* or changed timestamp refuses despite identical current Applied/LKG/latest candidate and `apply_history` ledger; malformed JSON with a matching SHA, half-present optional metadata and over-128 rows refuse. A separate Linux cross-language test uses **real Go v18 Store** to commit three generations; the oldest confirmed one remains retained but unselected, and its contents can be changed/rehashed only via test-only SQL. The unchanged guest report succeeds and remains read-only; the post-mutation report must refuse.

## Remaining bounds

The ledger observes **only generations still present** in the guest DB at baseline and verification. A legitimately pruned generation's original BLOB cannot be reconstructed from `apply_history` metadata; hash matches are not an external HMAC or signed archive. Baseline capture does not attest to earlier history or guarantee that the Core or VM ever ran. Missing external rule-resource inode content, crash/boot evidence, genuine electrical power-loss durability, credential-preserving restore transaction, multi-stage Core rollback, CN offline rule/license acceptance and 72h/7d/30d soak remain release blockers. All proof/restore/deletion flags remain false, and PR #1 stays Draft with stable `main` unchanged.
