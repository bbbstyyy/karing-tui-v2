# ADR 0136 — Canonical Go v18 inert-restore fence parity in guest auditing

- **Status:** M4 test-only, read-only contract enforcement. No power-loss/reboot validation, restore activation, signed-archive authentication, Core operation, or cleanup authority.
- **Dependency:** ADR 0135's full v18 `inert_restore_preparations` SHA ledger. This change targets only the disposable Python guest auditor, negative synthetic tests and Linux real-Go-v18 cross-language fixtures.
- **Constraints unchanged:** ordinary Linux user, no TUN, CN 28 built-in policy groups, Custom → GeoSite → GeoIP → ACL → FINAL layering, and no subscription/ISP routing layer.

## Rejection gap

ADR 0135 verifies `baseline_json` is a nonempty JSON object whose SHA-256 matches the v18 inert record. But the production Go reader `scanInertRestorePreparation` also requires the *exact canonical* `storage.InertRestoreFence` schema and `json.Marshal(fence)` bytes. With a newly pinned guest baseline, an adversarial test DB containing `{"ConfigRevision":1,"unreviewed":true}` plus a matching recomputed SHA could pass Python while the real Go Store refuses. A digest match alone does not establish that the bytes are a valid recovery-fence record.

## Decision

1. Require exactly the 16 exported `InertRestoreFence` fields in Go struct field order, with **no unknown or missing keys**: config/applied/LKG/declaration/selection identities; routing mode, private-direct and Core desired state; and all eight declaration/selection/applied/LKG content digests.
2. Mirror the production Go `validInertRestoreFence` field-domain preconditions: positive appropriately bounded revisions and generation IDs; selection revision nonnegative and within signed SQL bounds; lowercase 64-hex SHA strings; `rule/global/direct` routing, `stopped/running` Core desired state, and a real JSON boolean (not 0/1) for private-direct. A Python bool must never satisfy a numeric field.
3. Match *exact compact* `json.Marshal(InertRestoreFence)` bytes after parsing, not just a post-hoc SHA. Reject extra/missing keys, duplicate keys, field reorder, added whitespace, alternate escape encodings, incorrect enums and malformed typed/oversized values—even when `baseline_sha256` has been recalculated to match those invalid bytes. Inspect every v18 inert row, pending or abandoned, while preserving the existing 32-row read bound and 4096-byte JSON bound.
4. Increment **disposable guest witness format v4 → v5**. Older witness files are not migrated or overwritten. Continue to produce only redacted counts and ordered SHA digests. No raw scope, archived error, serialized fence or credential may leave the private audit.
5. Update synthetic Python fixtures to use a canonical **Go-shaped** 16-field, ASCII-only payload; test valid pending and abandoned, incorrect JSON shape/whitespace/order/rehashed unknown field, bool-vs-int and invalid enums/hashes. A fresh Linux real-Go-v18 SQLite test obtains a production-created prepared inert record, then for each invalid case rewrites only temporary `baseline_json` and its stored SHA; **before any guest capture**, Python must refuse cleanly and Go's own `InspectInertRestoreRecords` must also refuse. Verify the Python attempt did not write SQLite bytes.

## Explicit non-authority

This is a syntax/domain agreement between two readers, **not** a signed statement that the old fence is still current or a durable lease. Even canonical metadata could be stale or maliciously substituted before its external SHA is pinned. It neither accesses real candidate ciphertext nor verifies HMAC, VM stop/reboot, file/inode provenance, live Core traffic, physical power failure, user credentials, or full restore/rollback safety. T15/T23/T25, durable cross-resource recovery and the 72h/7d/30d stability matrix remain open; `RestoreSupported=false`, `RestoreReady=false`. PR #1 stays Draft and stable `main` unchanged.
