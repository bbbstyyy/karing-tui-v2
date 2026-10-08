# ADR 0067: Bounded profile node summaries and revisioned overlays

## Status

Accepted.

## Context

M3 stores immutable subscription snapshots and per-node disabled/favorite/alias/order overlays, but prior to this change there was no protected local API to list stable node IDs and edit these user choices. Source keys and node payloads can contain proxy credentials, so neither should be exposed by a node list endpoint.

## Decision

- `GET /v1/profiles/{profile_id}/nodes?offset=0&limit=100` returns a snapshot-consistent page in source order (maximum limit 200). The payload includes snapshot ID, total count, stable node ID, safe source/display names and overlay fields/revision. Unknown and repeated query keys are rejected.
- `PUT /v1/profiles/{profile_id}/nodes/{node_id}/overlay` accepts strict JSON with `expected_revision` and full `overlay`. The same per-profile gate used for source edits/refresh serializes writes. SQLite's existing CAS rejects stale revisions and changes to unavailable current nodes.
- The read-only SQLite transaction joins a bounded page of nodes with overlay states, without reading source payload JSON. Source keys and credentials are never returned.
- An overlay change does **not** advance the immutable snapshot, declaration or active runtime generation. An explicit snapshot-to-declaration update and revisioned apply remain necessary.

## Validation

Storage/API regression fixtures cover bounded pagination, overlay joins, malformed requests, stale CAS, missing nodes, hidden credentials, and unchanged snapshot/declaration revisions.

## Constraints

This does not enable unsupported Karing filter grammar, subscription/ISP routing, or URLTest regex expansion. CN offline license/resource closure remains a release blocker.
