# ADR 0026: Persist config, manifest, and source map as one immutable generation

- Status: Accepted
- Date: 2026-10-06

## Context

The compiler now emits more than native sing-box JSON. Correct recovery and explanation also depend on the exact resource manifest and route source map that were compiled with those bytes.

Persisting only `config_json + config_sha256` allows a later process to reconstruct or substitute metadata from a different compiler run, resource closure, or source revision. That would weaken rollback auditing and make route explanations unverifiable after restart.

The storage layer must not import compiler package types because persistence is a lower-level dependency.

## Decision

SQLite schema v3 extends each immutable generation with nullable legacy-compatible columns:

- `manifest_json`
- `manifest_sha256`
- `source_map_json`
- `source_map_sha256`

The database stores opaque JSON bytes and hashes. It does not interpret compiler-specific fields.

Existing generations remain valid with NULL metadata. New strict compiler/apply paths use `PrepareApplyWithMetadata`, which requires both manifest and source map to be non-empty valid JSON and limits each document to 16 MiB.

The existing 64 MiB native-config limit is unchanged.

## Hash identity

Each persisted byte sequence is hashed independently with SHA-256 before insertion.

The apply journal continues to expose the native config SHA-256 because that is the identity consumed by the generation runner. `GenerationArtifacts` exposes all three byte sequences and hashes for audit, recovery, and future file staging.

Returned byte slices are copies; callers cannot mutate database-owned state.

## Compatibility

The original `PrepareApply` API remains available and stores NULL metadata. This is necessary for already-written tests and for reading generations created before the compiler metadata contract existed.

The strict managed-apply compiler path must migrate to `PrepareApplyWithMetadata` before `managed_apply` can become true.

Schema migration uses additive nullable columns so an existing v1/v2 database can preserve all previous generations without fabricating metadata that did not exist at creation time.

## Transaction boundary

Config, manifest, source map, their hashes, the generation row, and the prepared apply-journal row are inserted in the same SQLite transaction.

A failure before commit leaves no partially paired generation metadata.

Network I/O and core process operations remain outside that transaction.

## Remaining work

- serialize the compiler's native manifest and route source map into this strict prepare call;
- stage/verify the persisted metadata as generation files if needed for offline inspection;
- make recovery verify the manifest's referenced content-addressed artifacts before starting or rolling back a generation;
A dedicated historical v2 database fixture now exercises the additive v3 migration and verifies that config revision, applied/last-known-good generation, core desired state, committed journal, and legacy config bytes/hashes survive unchanged while new metadata columns remain empty.
