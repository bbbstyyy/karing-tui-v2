# ADR 0182 — Stage-phase diagnostics for intermittent inert candidate refusal

Status: implementation pending exact-head CI (Issue #59; T15/T23 reliability).

## Motivation

A prior CI job failed while staging an encrypted restore candidate, even
though a separate read-only authenticated archive preflight, SQLite logical
verification and disk-reserve check all passed after the refusal. Repeating
the same commit succeeded. The flattened `ErrUnsafeInertRestoreCandidate`
does not reveal which internal admission boundary refused the candidate.
The cause remains unknown; a successful rerun is not root-cause proof.

## Decision

Keep the exported `StageInertRestoreCandidate` API and every production
refusal exactly as before. Internally delegate to a stage function accepting
a **test-only nil-by-default callback** with fixed, bounded phase labels:
source preflight, disk reserve, parent lock/inventory, scope creation and
lease, ciphertext copy, scope/parent fsync and candidate revalidation.

In the shared test fixture, record the last reached label and emit it only
when the fixture fails. This is not a new product metric, user interface,
public API, backup command, restore permission or cleanup pathway. No
path, hostname, archive digest, key, filesystem content or credentials are
included in the phase label. No automatic retries are added.

A deterministic fault-injection regression refuses each critical boundary
and asserts no retained new candidate scope, no source ciphertext deletion,
and no candidate restoration authority; then verifies normal staging.
An internal probe refusal returns the same public sentinel as a safety
check and uses the existing exact-ownership cleanup path.

## Evidence limits

This provides **phase localization** for the next recurrence, not a proven
fix for the intermittent failure. Issue #59 stays open until repeatable
root-cause evidence and a causal regression are obtained. T15/T23 recovery
and all release gates remain blocked where they already were. No TUN,
subscription/ISP routing layer, core change, privileged operation, public
network requirement or stable `main` modification.

Merge only after exact-head ordinary CI, four Race shards, Managed Core and
both native Linux Core Provenance jobs have succeeded.
