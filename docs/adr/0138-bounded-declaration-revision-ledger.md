# ADR 0138 — Complete bounded declaration revision chain in disposable guest replay

- **Status:** M4 Linux guest-only read-only audit; not accepted for T15/T23 actual reboot/power loss, Core health, real user backup restoration or cleanup.
- **Depends on:** ADR 0130–0137, v18 `declaration_state` and append-only `declaration_revisions` created by production Go Store `CommitDeclaration`.
- **Operating constraints:** Linux ordinary user, no TUN; preserve CN's 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL, and exclude subscription/ISP routing.

## Why

Earlier guest audits pin applied/LKG generation BLOBs, all retained generations, selected target state and archived apply journal. A separate immutable chain of **routing/DNS source declarations** exists in `declaration_revisions`. A *noncurrent historical* declaration document could change with its SHA-256 recalculated without altering applied generations, newest declaration semantics, selection, core state, or the preexisting ledgers. Stable crash replay needs evidence of that history's immutability, rather than treating a current config digest as covering every declaration.

## Decision

1. Advance the **disposable guest document** format **v6 → v7**, preserving independently pinned SHA witness rules. Do not migrate SQLite (still v18) or reuse/overwrite prior witness files; a new nonce and owner-private guest state are required.
2. Under the same WAL-aware SQLite `mode=ro` snapshot, read the exactly-one `declaration_state` singleton and all `declaration_revisions` in ascending order, hard-capped at **128** rows (fetch 129 then refuse). The source data is an append-only 1..N chain: revision 1 has NULL parent, revision i>1 has parent i−1; the singleton current pointer must equal N or be NULL when N=0. A gap, wrong parent, inconsistent pointer, or overflow refuses.
3. Validate each nonempty `document_json` as JSON at **≤16 MiB**, independently recomputing the lowercase SHA-256 and rejecting malformed constants even when their SHA is recomputed; validate source against Go's 1..128 ASCII `[A-Za-z0-9_./:-]` contract and owner-bounded timezone-aware creation timestamps. This is consistency with a bounded Go data model, **not** a routing-policy compiler or a signed provenance proof.
4. Digest every retained revision ID, parent ID, content SHA, BLOB length, source identifier and creation time in a canonical ordered UTF-8-safe representation. Pin only `declaration_record_count`, `declaration_current_revision`, and `declaration_ledger_sha256` into the private audit. Do **not** expose any plaintext routing, DNS, node or profile content, source name or timestamps in user-facing reports. Both original strict `verify` and prepared-only `reconcile-verify` must preserve the whole declaration ledger unchanged.
5. Python synthetic fixtures include empty declaration baseline, valid 2-revision chain, old doc replacement+matching SHA, malformed parent/pointer, invalid source, JSON NaN with matching SHA, and >128 revisions. Real Linux Go v18 Store cross-language test creates two declarations using production CAS transactions, captures and verifies against the original Python reader without any SQLite writes from it, then modifies/re-hashes **only the older** retained declaration row in disposable SQLite and requires independent refusal.

## Explicit exclusions

This ledger covers SQLite declaration metadata and JSON contents only; it does not reproduce Karing's complete rule engine, confirm native rule-file inode closure, validate external GeoSite/GeoIP resources, Core's running route/DNS health, archive HMAC, electrical power-loss durability, VM restart witness, credential-preserving restoration, cleanup rights or 72h/7d/30d long soak. Historical revision hashes are not signatures or an authorized restore token. No daemon/TUI/CLI production operation, SQLite migration, Core state change, TUN or backup import is added. T15/T23/T25 remain OPEN; `RestoreSupported=false`, `RestoreReady=false`, PR #1 Draft, stable `main` unchanged.
