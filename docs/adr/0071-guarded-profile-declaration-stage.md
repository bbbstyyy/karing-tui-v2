# ADR 0071: Guarded profile declaration staging

## Status

Experimental (not yet a production apply path).

## Decision

`POST /v1/profiles/{profile_id}/declaration/stage` accepts the current accepted snapshot ID, expected source revision, expected declaration revision, candidate SHA-256 and runtime overlay SHA-256 from the read-only preview. The server rematerializes the snapshot and overlays, recomputes the candidate bytes, and rejects any digest discrepancy. It then commits one immutable declaration revision only after transactional validation of the profile source revision, current snapshot pointer, every persisted overlay revision, and the declaration CAS revision.

Stage is intentionally separate from `/v1/declaration/apply`. The operation does not run a core check, change the active generation or restart any process. Application still requires the existing explicit compile/apply workflow and audited resources.

Only enabled profile sources are eligible; disabled sources fail closed. The read-only preview includes the source revision in its safe response and rechecks overlay revisions before responding; staging rejects a source edit even when the old snapshot and both payload hashes remain unchanged. Staging uses the original source revision rather than accepting a newer source version after a concurrent change. The per-profile API gate reduces conflicts with manual profile mutations, but the storage transaction is the authoritative concurrency boundary; background refresh and multi-profile declaration mutations still require CAS protection. Digest acknowledgement is a state-consistency guard, not evidence that a generated native configuration can run safely.

## Remaining work

- Expose stage using `karing-tui profiles stage <id> --snapshot-id=N --expected-source-revision=N --expected-declaration-revision=N --candidate-sha256=HASH --runtime-overlay-sha256=HASH --confirm` after inspecting the independent read-only `profiles preview` result; all stage parameters are mandatory and daemon errors are redacted.
- Complete CI and race/integration checks, including stale source/snapshot/overlay revisions, concurrent stage writers and non-mutation of live core state.
- Add end-to-end approved-core validation before any promotion-to-apply shortcut.
- Do not import subscription/ISP routing or weaken the no-TUN or CN offline requirements.
