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

## 2026-10-29 follow-up: exact failed-stage evidence

The new CI race (2/4) on head `0f881e065df28b` captured a second
stage refusal at `stage=create_scope` in
`TestSealedCompletionRequiresAllLeavesGoneAndRetainsEveryProof`. Independent
preflight, SQLite and disk-reserve checks passed. The original checkpoint
could not distinguish `MkdirTemp` refusal from subsequent child-directory
open/flock/identity refusal. No cause has yet been established.

The stage probe now exposes distinct **test-only** checkpoints after creating
the exact empty scope and within the opened child (directory fd, exclusive
flock and inode/permission checks). All injected failures close descriptors,
remove only the empty scope created by this call or use the existing
ownership-safe discard path. Production remains nil-probe; the public error
is unchanged. This improves repeatability and narrows future evidence, but
**does not turn the recurring failure into a pass or close Issue #59**.

The same head also failed managed-core dependency download at
`github.com/sagernet/sing-shadowtls@v0.2.1` with HTTP/2 INTERNAL_ERROR
from the Go module proxy. Do not change the pinned dependency or assert a
source-code defect from this network-layer failure. Require a new exact-head
managed-core green result before merge.
