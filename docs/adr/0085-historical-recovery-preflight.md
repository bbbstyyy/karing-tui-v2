# ADR 0085: Read-only historical runtime-binding preflight

- Status: M4 partial prerequisite; manual restore remains prohibited.
- Scope: Linux user-space proxy, no TUN, no subscription/ISP routing layer.

A retained historical generation with valid hashes is not necessarily compatible with the *current* runtime intent. Extend the confirmed-generation audit with a bounded, read-only preflight. On a fully retained and verified payload, parse its immutable declaration and validate the current persisted CurrentSelected target against that historical candidate set and the outbound tags embedded in its manifest. A missing or malformed intent fails closed; it is never replaced with a previous default. Check the fixed three proxy inbound tags and DIRECT/CurrentSelected outbound tags as structural evidence, and confirm that the current routing policy and desired core state are recognized.

The API exposes only `preflight_status`: `not_checked`, `state_not_quiescent`, `selector_incompatible`, `runtime_policy_incompatible`, or `bound_state_consistent_only`. None of these is an authorization. The older `stored_integrity_verified_only` status remains about stored bytes and resources, not restored behavior. The report never returns selector IDs, native configuration, domain rules, credentials, or paths.

Audit now re-reads the selector revision/bytes, routing mode, private-direct switch, desired core state, generation pointers, active attempt, current declaration and bounded committed generation inventory. Any observed change rejects the entire report with 409. This is optimistic race detection, **not a durable SQLite lease**; a restored historical generation would still require transactionally pinned resources, runtime/core binary compatibility, a core check, atomic CAS journal, activation, live verification and rollback-of-rollback fault injection. `restore_supported=false` and every `restore_ready=false` remain invariants.

Existing automatic apply rollback is unaffected. P0 multi-layer route order, CN preset and subscription/ISP exclusion are unchanged.
