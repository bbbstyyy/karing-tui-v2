# ADR 0071: Guarded profile declaration staging

## Status

Experimental (not yet a production apply path).

## Decision

`POST /v1/profiles/{profile_id}/declaration/stage` accepts the current accepted snapshot ID, expected declaration revision, candidate SHA-256 and runtime overlay SHA-256 from the read-only preview. The server rematerializes the snapshot and overlays, recomputes the candidate bytes, and rejects any digest discrepancy. It then commits one immutable declaration revision only after transactional validation of the profile source revision, current snapshot pointer, every persisted overlay revision, and the declaration CAS revision.

Stage is intentionally separate from `/v1/declaration/apply`. The operation does not run a core check, change the active generation or restart any process. Application still requires the existing explicit compile/apply workflow and audited resources.

The per-profile API gate reduces conflicts with manual profile mutations, but the storage transaction is the authoritative concurrency boundary; background refresh and multi-profile declaration mutations still require CAS protection. Digest acknowledgement is a state-consistency guard, not evidence that a generated native configuration can run safely.

## Remaining work

- Expose stage through a credential-safe CLI workflow with explicit acknowledgment parameters.
- Run CI, formatting and race/integration checks against this branch and fix any failures.
- Confirm source/overlay race semantics under concurrent refresh and stage, then add end-to-end approved-core validation before any promotion-to-apply shortcut.
- Do not import subscription/ISP routing or weaken the no-TUN or CN offline requirements.
