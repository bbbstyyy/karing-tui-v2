# ADR 0109 — Stable archived apply lifecycle attestation before sealing or preflight

- Status: **M4 internal-only archive consistency gate**, not backup import, restoration, or activation.
- Builds on ADR 0094–0108; SQLite schema remains **v18**.
- Linux ordinary user, no TUN, CN 28 original groups, Custom → GeoSite → GeoIP → ACL → FINAL; no subscription/ISP routing.

## Problem

An internally generated, WAL-consistent SQLite copy is consistent **as of a point in time**, but that point may be midway through an apply or after a failed rollback. The archive reader previously validated database integrity, exact schema, declarations, profile data and native generation hashes, but did not require a settled apply lifecycle. Similarly, retained `generations` bytes by themselves did not prove that `daemon_state.applied_generation_id` was successfully committed at `config_revision`. A cryptographically correct sealed archive could thus carry ambiguous runtime authority.

Separately, a pending v18 *inert restore* preparation cannot safely be imported: ADR 0107 deliberately forbids read-only preflight of an archive containing such a row. The archive writer now runs the same archived-schema/domain audit on its **own immutable SQLite copy**, so it refuses that case before allocating and sealing a doomed archive.

## Decision

`storage.verifyArchivedStableLifecycle` is called by `VerifyArchivedSchemaAndDomains`, which is used by **both** the immutable snapshot closure builder and the independently authenticated, in-memory sealed archive reader. It inspects only the supplied snapshot connection; it does not read the mutable daemon state separately.

For an archive with an applied configuration, the check requires:

1. No `apply_journal.active_slot=1` and `daemon_state.recovery_required=0`. Historical *terminal*, inactive failed/interrupted attempts do not by themselves block inspection.
2. A positive `config_revision`, retained positive Applied and LKG generation IDs, and an Applied generation whose `target_revision` is exactly the committed configuration revision.
3. **Exactly one** matching committed attempt record for each referenced generation, counting the current `apply_journal` and retention-compacted `apply_history` together. LKG may refer to an older generation but never to a future revision. IDs or stored config bytes alone are insufficient evidence of a committed generation.

An unconfigured database with revision zero and **both** Applied/LKG absent remains eligible for bounded *inspection*, not activation or restore. Revision zero with generation pointers, a nonzero revision with missing LKG, duplicate committed evidence, or lifecycle/phase drift fails closed.

The validation is read-only: no SQL import, journal transition, core check, restart, restore attempt, plaintext materialization, change to the live generation, or cryptographic key custody. The existing `RestoreSupported=false` and `RestoreReady=false` flags remain unconditional.

## Verification and boundaries

- Builder regressions check active real `PrepareApplyWithMetadata` attempts, injected `recovery_required`, pending/invalid inert preparations, and preservation of live state and temporary-scope cleanup on refusal.
- Reauthenticated encrypted archives with **valid HMAC and resource hashes** but tampered lifecycle rows must fail schema/domain preflight.
- Retention-compacted successful attempts in `apply_history` are accepted; no-generation initial state is accepted as nonrestorable.
- Original v17 sealed archives continue as read-only audit candidates under their own schema reference. No schema migration is introduced.

This closes a **necessary** archive consistency precondition, not a sufficient recoverability proof. The snapshot copy may be captured during unrelated daemon changes after its own consistency point, and no archive is yet a restore permit. True restore still requires isolated SQL import, pinned/executable resource re-check, daemon operation gate, same-transaction CAS with durable activation, core Check/Activate/Verify, safe rollback-of-rollback, large-database verification and T15/T23 power-loss injection. CN offline resource and license closure and 72h/7d/30d stability evidence remain separate release gates. Keep PR #1 Draft.
