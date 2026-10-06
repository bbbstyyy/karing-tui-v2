# ADR 0037: Bind declaration rule sets through immutable content addresses

- Status: Accepted
- Date: 2026-10-06

## Context

The routing compiler already understands logical rule-set references and the managed-core adapter already verifies rule-set files recorded in generation manifests. The missing trust boundary was how a declaration could name a rule set without being allowed to inject an arbitrary filesystem path or depend on mutable "latest" content.

The project plan requires offline operation, immutable runtime resources, bounded inputs, fail-closed missing references, and no compiler network I/O.

## Decision

Declaration schema v1 now permits a top-level `rule_sets` collection. Each entry contains only:

- a logical `ref` used by route predicates;
- an exact SHA-256 digest;
- a declared format (`source` or `binary`).

Declarations never carry runtime filesystem paths.

Rule-set bytes enter the daemon through:

`PUT /v1/rule-sets/{sha256}?format=source|binary`

The request body is streamed with a 64 MiB upper bound into the existing private core artifact store. The daemon verifies the requested SHA-256 before publishing the file at:

`state/core/rule-sets/sha256/<sha256>.json`

or

`state/core/rule-sets/sha256/<sha256>.srs`.

Publishing uses the existing private content-addressed storage rules: mode 0600 files, private directories, immutable destination names, fsync, and no symlink-following for verified runtime files.

## Declaration validation and compilation

For active routing rules, every logical rule-set reference must have declaration metadata.

When the daemon resource store is available, declaration commit validates that every active referenced digest already exists and passes the stored-file SHA-256 verification. Missing resources therefore prevent the declaration head from advancing.

During native compilation the declaration compiler resolves only the active rule-set closure, constructs the existing compiler `RuleSetCatalog`, rewrites logical refs to stable runtime tags, and binds exact content-addressed paths. Unused or disabled rule-set metadata is not loaded into the native generation.

Compile preview and apply fail closed if a referenced resource later disappears or is modified.

## Format boundary

Resource ingestion validates the bounded byte count, requested format class/extension, immutable path, and SHA-256 identity. It does not claim that an arbitrary uploaded `.json` or `.srs` is semantically valid for the selected sing-box build.

Semantic/format compatibility remains part of candidate native-config checking by the pinned core before activation. A failed core check does not replace the currently applied generation.

SHA-256 proves identity of the bytes, not trust in their origin. Trusted CN/offline manifests still need pinned source, version, license, and hash metadata.

## Consequences

- arbitrary declaration-controlled file paths remain impossible;
- compiler execution performs no network I/O;
- a declaration is reproducible from its revision plus exact resource digests;
- missing or tampered resources cannot silently degrade to DIRECT or disappear from routing;
- runtime restart and rollback keep re-verifying manifest-bound rule-set files;
- future rule-package download/update logic can publish into the same content-addressed store without changing declaration semantics.
