# ADR 0098 — Canonical inert closure inventory verification

- Status: M4 **internal-only validation prerequisite**. No archive export, restore, or activation.
- Dependencies: ADR 0094–0097 and `docs/plan.md` §§13, 18, 20.
- Target: Linux-only user-mode, no TUN; preserve CN 28 groups and Custom → GeoSite → GeoIP → ACL → FINAL without subscription/ISP routing.

## Decision

`backupclosure.ParseInertInventory` accepts only exact, canonical `encoding/json.Marshal(Inventory)` bytes with a matching lowercase SHA-256. Input is capped at 128 KiB. Canonical re-serialization rejects unknown or duplicated keys, noncanonical whitespace and extraneous values. Both manifest versions must match the pinned SQLite schema, contain positive bounded database size, explicit generation/rule arrays, immutable sorted unique generation IDs and rule relative paths, supported rule formats and SHA-256 content-addressed filenames. Each rule is limited to 64 MiB and the union to 128 MiB. v1 must have no core; v2 must have exactly the locked architecture/hash/commit/version identity and a bounded non-executable core copy metadata entry. The conservative credentials flag remains true; **restore_ready may never be true**.

`Closure.Verify` checks the same structural rules against its live immutable scope and binds its database hash/size to the inventory, plus every ordered pinned rule's hash, format, basename and byte count to a matching inventory entry. Existing checks continue to rehash held file descriptors, independent private copies and the SQLite snapshot. Inventory digests remain canonical but *not authenticated*; a malicious actor who controls both JSON and the supplied checksum could fabricate consistent metadata.

## Exclusions and tests

This does not establish file possession for standalone inputs; the parser performs no filesystem access. It does not encode credentials, encrypt/sign artifacts, offer import/export, preserve resource leases across process death, or provide a historical restore permit. No daemon, CLI, HTTP or TUI API is added. Tests cover both manifest versions and malformed or forged metadata, including duplicate or unexpected keys, path traversal, digest tampering, oversized payloads and altered held-closure inventory.

Restore remains unsupported (`restore_ready=false`). The next release gates remain durable encrypted archive transport, exact resource re-verification at restore time, versioned migration, two-phase transactional restore with rollback-of-rollback and T15/T23 failure injection.
