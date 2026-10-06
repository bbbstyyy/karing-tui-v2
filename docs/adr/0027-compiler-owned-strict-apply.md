# ADR 0027: Only compiler-owned artifacts may enter strict managed apply

- Status: Accepted
- Date: 2026-10-06

## Context

Schema v3 can persist a native config, manifest, and source map together, but accepting those three byte blobs from an external API would allow a caller to forge audit metadata that does not correspond to the config actually checked and activated.

The compiler already owns all information required to produce those metadata documents.

## Decision

The compiler artifact becomes the trusted handoff object.

`NativeConfigArtifact` now carries:

- exact native JSON;
- native JSON SHA-256;
- typed manifest;
- a deep copy of the generated route source map.

`MetadataJSON()` deterministically serializes the manifest and source map with fixed snake_case field names.

The daemon adds `CompiledGenerationArtifacts` and `ApplyCoordinator.ApplyCompiled`. The strict path requires the storage backend to implement `PrepareApplyWithMetadata`; it never silently falls back to the legacy config-only prepare call.

`serverRuntime.ApplyNativeArtifact` is the internal composition boundary. It accepts a typed `compiler.NativeConfigArtifact`, serializes metadata itself, and then enters the same operation gate and apply coordinator used by normal activation.

## Compatibility

The existing `Apply` and `ApplyCompiled(config []byte)` paths remain for internal compatibility and existing tests. They do not imply that arbitrary native JSON is a supported public managed-apply API.

The daemon must not expose a public endpoint that accepts caller-supplied manifest/source-map JSON.

## Integrity properties

The strict path copies config, manifest, and source-map byte slices before preparation.

Storage validates metadata JSON and persists all three artifacts and their hashes in one SQLite transaction before core `check`.

The candidate passed to the core is built from the same copied config bytes whose SHA-256 is recorded in the generation row.

## Remaining work

- route declaration revisions through the compiler and `ApplyNativeArtifact`;
- remove or further quarantine the legacy config-only apply path once migration compatibility no longer needs it;
- verify persisted manifest resources during restart/rollback;
- persist compiler diagnostics and declaration revision identity alongside the generation.


## Integration coverage

The real managed-core integration now applies successful compiler candidates through `serverRuntime.ApplyNativeArtifact`, not the legacy config-only path. The fixture asserts that manifest/source-map bytes and hashes are present in SQLite before explicitly starting the committed generation.

That explicit start then passes through persisted-generation resource re-verification before the approved core is launched, so the integration exercises the strict handoff across compiler, SQLite transaction, generation staging, core `check`, activation, restart, and lifecycle control.
