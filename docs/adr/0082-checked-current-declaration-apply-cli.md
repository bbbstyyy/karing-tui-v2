# ADR 0082: Guarded explicit application of the current unapplied declaration

## Status

Accepted as a bounded **M4 CLI** apply workflow, not a complete configuration/rollback UI. Linux, ordinary-user proxy mode, no TUN; Karing's five routing layers and pinned CN resources remain unchanged. Subscription/ISP routing remains excluded.

## Intent and guard

The existing `POST /v1/declaration/apply` accepts explicit historical immutable declaration revisions and only uses a runtime config revision CAS. That is useful for low-level recovery, but not a safe default for the operator's *currently staged* declaration. This ADR adds two separate endpoints and commands:

- `GET /v1/config/apply/preview`: acquire the daemon operation gate, read the verified current declaration revision/SHA, config revision, nullable applied-generation ID and CurrentSelected revision, refuse recovery or an active apply, and reject an already-applied current head. Strictly compile the immutable current declaration using the pinned managed compiler and local resource resolver; re-read the identity after compilation. Reply with only safe counts, schema ID, native SHA and a five-field identity receipt. Preview returns `compiler_validated=true`, `core_validated=false`, `applied=false`; neither core check nor durable apply occurs.
- `POST /v1/config/apply/confirm`: accept the receipt ONLY; under a single non-reentrant operation gate, compare current declaration SHA/revision, config revision, applied-generation ID and CurrentSelected revision; verify it is not already applied; recompile and compare the exact native SHA, then recheck identities. Invoke the existing trusted `applyNativeArtifact` under that same gate, which calls managed core `Check -> Activate -> Verify -> CommitApplied`. Success records the newly committed revision/generation and returns `core_checked=true`, `verified=true` and `applied=true`.

A mismatched digest, concurrent declaration edit, selection revision or applied generation returns a conflict before core I/O. A corrupt receipt or failed strict compile is rejected; provenance uncertainty fails closed. Both endpoints omit native JSON, upstream DNS hostnames, rule matcher values and node credentials. Response errors are deliberately generic to avoid leaking managed core stdout or source configuration. Note that arbitrary legacy declaration/profile commits can occur outside this operation gate; immutable snapshot compilation plus a final authority check prevents ordinary stale confirmations, but the current endpoint does not create an SQLite compare-and-lock spanning *all* legacy declaration mutators. Do not equate this with a global database-wide serialization of every historical API.

## CLI receipt and operational semantics

`config apply-preview --out=FILE` creates a new `0600` JSON receipt with exclusive creation. `config apply --receipt=FILE --confirm` opens the inode without following symlinks, enforces size, regular-file, owner and private-permission checks, validates exact JSON/required fields and performs **one** confirmed write. The apply may replace a running core and interrupt connections. It is not a TUI navigation side effect.

After a successful HTTP acknowledgement, the CLI reads status once and verifies durable config revision and generation ID; it does not print raw core errors. A timeout or missing/mismatched readback is treated as uncertain and **never causes an automatic retry**; the user must inspect status and recovery. The coordinator's existing rollback attempts restore the preceding generation on activation/verification failures; if that rollback fails, recovery-required remains the authority. This is not a manual selection of an old generation, and does not close M4 recovery UX, T10 DNS detour observation, immutable backup/restore, or 72h/7d/30d release gates.
