# ADR 0103 — Exact SQLite DDL attestation and bounded profile-domain audit

- Status: **M4 internal-only read-only preflight prerequisite**. Not an import, restore, activation, or published backup format.
- Dependencies: ADR 0094–0102; `docs/plan.md` §18/T15/T23.
- Linux unprivileged/no TUN. CN's 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL routing remain unchanged, without subscription/ISP routing layers.

## Schema attestation without a second hand-maintained migration map

The archive's SQLite bytes must first pass the full encrypted archive HMAC, all resource digests, complete ciphertext hash replays, in-memory-only deserialization, `integrity_check`, `foreign_key_check`, and the 17 ordered migrations (ADR 0102).

`storage.VerifyArchivedSchemaAndDomains` then opens a **separate `:memory:` reference SQLite database**, runs the currently pinned `Store.migrate` procedure on that reference only, and compares the entire ordered `sqlite_schema` catalog to the untrusted archive's read-only connection: object kind, name, table name, and exact DDL SQL including tables, indexes, autoindexes, and triggers. A maximum of 128 objects and 1 MiB of catalog text is allowed. No DDL is run on the archive connection; no additional trusted schema fixture can silently drift from the actual migration source. Additional, missing or altered schema objects fail closed, even if `schema_migrations` reports a supported version.

Migration code and driver version constitute the reference contract: benign cross-version SQLite DDL normalization or new optimizer-created persistent schema objects can be rejected until explicitly reviewed. This is intentionally stricter than `PRAGMA integrity_check`. The reference database exists in process memory and is destroyed after inspection.

## Domain-state binding and bounded inspection

The same already-verified private SQLite connection is queried with fixed SQL only. The audit validates all retained profile snapshot headers, original source metadata, and node payloads. Each node is checked in **ordinal order** starting at zero, with a valid stable node ID, bounded source key/name, bounded nonempty JSON payload, and matching SHA-256; the total payload per snapshot remains at most 64 MiB. A maximum of 4096 snapshots and 65,536 total nodes is allowed.

Every profile state pointer to a current or previous snapshot must refer to a snapshot owned by the *same* profile, not just a foreign-key-valid snapshot from a different profile. Profile subscription sources reuse the existing persisted `scanProfileSource` validator (source URL/file policy, format, update interval, filter, usage timestamps, fetch mode and lease fields) for up to 2048 entries. Up to 65,536 node overlay records reuse `scanProfileNodeOverlay`, with a maximum of 8192 overlays per profile. Overlay references to a node removed in a prior profile refresh are intentionally not treated as a live foreign-key requirement; they are never used to bind a restore. Selection-state payloads must be bounded valid JSON with a timestamp when present.

All count caps are **rejection bounds**, not retention/deletion commands. The report exposes only numeric counts and a `SchemaCatalogVerified` flag. It never exposes subscription URLs, node names, request paths, credentials, payload JSON, raw schema DDL or errors returned from SQLite.

## Fail-closed evidence and exclusions

Tests seal genuine profile/node/source/overlay data and verify the independent preflight succeeds while leaving daemon state and the archive directory unchanged. They then rewrite the in-memory source database to inject missing/extra indexes or DDL, triggers, incorrect node payload hashes, invalid JSON/ordinals, cross-profile pointers, invalid subscription source/fetch/usage fields, malformed overlays and selection payloads, and seal each manipulated database with valid archive encryption/MAC/resource hashes. These cryptographically legitimate but semantically inconsistent archives must return an empty preflight with a generic error.

The preflight remains **read-only and non-authorizing**, and remains capped at 64 MiB of in-memory SQLite database bytes. The audit does not provide a durable resource lease, isolate/activate a candidate, migrate data across schema versions, verify every business-specific apply-journal invariant, attest original remote subscription content, or guarantee bounded memory independently of the SQLite driver. `RestoreSupported=false` and `RestoreReady=false` remain mandatory. T15/T23, backup key management and long-running M4/M5 release gates remain open.
