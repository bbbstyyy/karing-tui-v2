# ADR 0070: Read-only profile snapshot declaration preview

## Status

Accepted.

## Context

M3 refresh accepts immutable profile node snapshots while the applied declaration remains independent. Operators need a safe and explainable way to inspect the effect of a source refresh and disabled/sorted stable-node overlays before any change to the declaration or core. Source payloads can contain proxy credentials and untrusted text.

## Decision

A protected Unix-socket endpoint, `POST /v1/profiles/{profile_id}/declaration/preview`, requires a positive **current** `snapshot_id` and `expected_declaration_revision` as one strict, size-bounded JSON object.

The daemon checks the current source snapshot and base declaration revision, verifies the stored declaration SHA-256, materializes only compatible canonical profile nodes, applies disabled/order overlays, and invokes the existing declaration V1 node-replacement validator. It rejects missing required node references, oversized candidate declarations and changing source/declaration heads. The existing per-profile operation gate and a 20-second deadline bound preview work.

The response contains the candidate document SHA-256, overlay SHA-256, immutable snapshot ID and added/removed/retained node counts. It never returns candidate JSON, source keys, credentials or original error diagnostics.

## Boundaries

This is **read-only and schema-validating only**: `core_validated=false` and `applied=false`. It does not run the approved core checker, commit a declaration revision, apply a runtime generation or restart core. It does not initialize an absent base declaration or import subscription/ISP routing rules.

A future promotion operation must re-check current source snapshot, declaration revision, overlay digest and candidate hash and then use the approved core check and existing managed-apply transaction. Successful preview by itself is not permission to apply.

## Validation

API tests exercise a secret-bearing accepted snapshot, deterministic candidate hash, removed/disabled selected-node blocking, stale snapshot/declaration conflicts, unknown JSON fields and unchanged declaration/runtime revisions.
