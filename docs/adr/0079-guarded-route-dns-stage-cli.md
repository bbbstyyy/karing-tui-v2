# ADR 0079: Strict compiler-backed single-field Routing/DNS binding preview and guarded staging

## Status

Accepted as a narrow M4 staged-edit API and CLI slice, **not** automatic apply or a full Routing/DNS terminal editor.

## Scope and invariant

Linux unprivileged proxy-only runtime, no TUN. The five ordered routing layers remain Custom → GeoSite → GeoIP → ACL → FINAL, with CN's immutable 28-group preset and region auto-append retained. Subscription/ISP routing remains deliberately excluded. No API in this ADR edits layer order, matching AST, DNS resolver server/port, node credentials, subscription state, CN preset source files or generated region entries. FULL group DNS traffic-path equivalence still needs T10 controlled-core evidence.

A single proposal changes exactly one field on one existing group: **enabled**, a typed **target**, or the **group-role DNS profile binding** (empty value clears it). FINAL supports target only. The pinned CN group is modified by updating/adding a `cn_preset.overrides` entry, never by copying it into ordinary Custom groups; original declared groups preserve matcher and source provenance. Derived region entries are explicitly non-editable. The raw JSON patch preserves all unrelated node/selection/DNS/route content, and the candidate is re-parsed through schema v1 and compiled through the existing strict resolver, DNS and routing closure before any commit is allowed.

## API contract

`GET /v1/config/route-edit/context` emits only declaration revision+SHA, config revision, nullable applied-generation ID and selection revision. It refuses recovery/active apply and invalid authority. `POST /v1/config/route-edit/preview` takes these five expected identity fields, a typed layer/group and exactly one edit pointer. The daemon obtains the current declaration and persisted selection intent, checks the identity, patches the document only in memory, then compiles the **transient candidate** using exactly the current managed declaration compiler + pinned local rule-set resource resolver. A post-compile identity recheck rejects concurrent drift. It returns before/after typed target, enabled state and group DNS reference, origin, candidate-document SHA-256, native-config SHA-256, native schema and bounded counts; **no raw document, match values, DNS server or credentials**. The response always says `compiler_validated=true`, `core_validated=false`, `staged=false`, `applied=false`.

`POST /v1/config/route-edit/stage` requires the same complete patch and both exact preview digests. Under the daemon operation gate it **reconstructs and recompiles** the candidate; a mismatch returns **409** without writes. A duplicate/stale base, config or selection revision, changed generation or active recovery/apply also returns 409. Bad patch or failed strict compile/resource closure returns **422**. Successful staging uses the existing SQLite immutable `CommitDeclaration` CAS with a named source; it creates one new **unapplied declaration revision**, leaving config revision, core generation, traffic and desired state unchanged. The ordinary separate `POST /v1/declaration/apply` retains its existing verification/rollback contract; stage intentionally does not call it.

An ambiguous stage timeout or lost response may follow an SQLite commit; no client automatically retries. The caller must first inspect the latest declaration revision/hash. A successful stage response is not a live-core validation, DNS-path observation, or assurance that a later explicit apply can never fail.

## CLI and privacy

`config route-preview` discovers the non-secret context before preview and prints a complete receipt or uses `--out=PATH` to create a **new** private `0600` JSON file. `config route-stage --receipt=PATH --confirm` rejects symlinks, non-regular files, non-user-owned or group/world-readable receipts and reads bounded JSON. A receipt contains only required identity, typed reference labels and SHA-256 digests. No raw daemon validation/compile errors are printed, because their text can contain sensitive matcher values or DNS endpoints. No changes are made merely by navigating the TUI; its existing Routing and DNS pages remain inspection-only at this stage.

## Verification and release gates

Tests verify ordinary target/enable/DNS edit, FINAL target, CN preset overrides, derived region immutability, no-op rejection, validation and unchanged unrelated contents, preview/stage digests, no running-core mutation, stale legacy edits and changed CurrentSelected revision, conflict-only concurrent stages, missing compiler, sanitized errors, CLI explicit confirmation and receipt filesystem permissions, and Unix-socket 409 propagation. Format/vet/test/race/build and managed-core integration must pass on the final SHA.

Remaining: complete group/RuleSet/DNS editor and matcher editing, compiler-verified cross-group change plans, CLI/TUI explicit apply and last-known-good rollback UX, consistency backups/restore, real DNS detour behavior (T10), offline CN rule assets/licenses and M2/M3 parity, and sustained 72h/7d/30d gates. These are release blockers, not completed by this stage-only slice.
