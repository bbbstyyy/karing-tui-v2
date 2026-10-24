# ADR 0076: Atomic CurrentSelected revision and applied-generation CAS

## Status

Accepted as a daemon/storage/API M4 hardening slice. TUI selection remains read-only until a verified candidate-picker and confirmation UI is available.

## Problem

ADR 0049 persists typed selection intent before updating the live selector. The original unconditional PUT is used by older clients, but cannot safely implement read/confirm/write in multiple concurrent terminals: another client may change the selection or apply a new generation between GET and PUT. A timed-out live update is especially hazardous because the database may have committed even when the caller sees a 502 or transport timeout.

## Decision

Schema migration 16 adds monotonic `selection_state.revision`, initialized to 0. A legacy write increments this revision on every successful commit; it cannot silently bypass a concurrent guarded request.

`GET /v1/selection/current` now returns `selection_revision`, `config_revision`, `applied_generation_id` (nullable), `declaration_revision`, and `declaration_sha256` in addition to the existing typed target and persisted/live readback fields. IDs and declaration hashes are non-secret identity tokens; no decrypted credentials or raw declarations are included.

New `PUT /v1/selection/current/checked` takes a typed target and **all** five corresponding `expected_*` fields. A missing declaration SHA/revision is refused. The daemon verifies membership in the declaration bound by the exact immutable applied-generation manifest (including manifest hash), or the current declaration only if no generation has ever been applied. It refuses writes during recovery or an active apply. The store then atomically performs one SQLite update with predicates for selection revision, config revision, applied generation ID, absence of an active apply/recovery and (when no generation is applied) the current declaration revision. No network operations run in SQLite transactions.

The existing daemon operation gate serializes both legacy and checked selection PUTs against core start/stop/apply/recovery operations. The coordinator also serializes legacy and checked selection writes through live readback. SQLite still enforces CAS across concurrent callers. The separate checked route avoids changing the legacy client protocol without notice.

On conflict, the server returns **409** and makes no persistent write or live selector call. Invalid candidate membership returns **422**. After a successful durable CAS the daemon updates and reads back the running core selector. If the core is stopped it returns `applied=false`; a running core without a trustworthy applied generation is refused on the checked route. If live selection/readback fails after a durable commit, the API returns **502** with a sanitized error and the intent remains persisted, revision incremented. Clients must GET again before taking any further action; automatically retrying the stale request is prohibited.

Changing selection does not create a new route declaration, apply a generation, or modify CN presets and the five-layer routing order. Subscription/ISP diversion remains excluded.

## Verification

Storage tests cover first-write revision 0→1, legacy revision invalidation, conflicting concurrent CAS writers, persistence across reopen, stale declaration/config revision and active apply refusal. Coordinator/API tests cover generation/hash binding, applied vs newer unapplied declarations, stale and invalid candidate rejection, successful live readback, stopped core, post-commit live failures and stale retry refusal. The socket client test verifies complete request fields and propagates 409 without automatic retry. Existing live-core integration and race tests are release gates.

## Next steps

Expose the exact membership list via a bounded daemon read endpoint or a safe selection GET expansion, then add a confirmed TUI picker using these CAS fields. On conflict or uncertain live readback it must discard the proposal and GET again. Full routing/DNS compatibility, CN offline rule-resource license closure, and long-duration stability gates remain open.
