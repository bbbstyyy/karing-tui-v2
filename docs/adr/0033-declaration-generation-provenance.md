# ADR 0033: Bind strict runtime generations to exact declaration revisions

- Status: Accepted
- Date: 2026-10-06

## Context

Schema v4 separates immutable declaration revisions from compiled runtime generations, but a generation manifest did not yet identify which declaration revision produced it.

Without that link, a later compiler coordinator could compile a declaration and apply a valid native artifact while losing the durable audit relationship between user intent and runtime state.

The two revision counters intentionally have different meanings:

- declaration revision: immutable requested configuration intent;
- runtime config revision: successfully committed core generation sequence.

They must not be assumed to be numerically equal.

## Decision

`compiler.NativeManifest` now carries optional declaration provenance:

- `declaration_revision`;
- `declaration_sha256`.

`NativeConfigArtifact.BindDeclaration(revision, sha256)` validates and binds those fields to a deep copy of the compiler artifact.

Binding also re-verifies:

- the exact native JSON bytes match the artifact config SHA-256;
- the manifest schema is the approved compiler schema;
- the manifest config SHA-256 matches the artifact.

## Strict apply boundary

`serverRuntime.ApplyNativeArtifact` now requires declaration provenance.

An artifact cannot enter compiler-owned strict apply if declaration provenance is absent or partial, the revision is zero, SHA-256 is malformed, or config/manifest identity was tampered after compilation.

The native core JSON itself is unchanged by this binding. Declaration identity is audit metadata, not a sing-box runtime option.

## Backward compatibility

Existing persisted generations from before schema v4 may contain compiler metadata without declaration provenance.

ManagedCore therefore accepts a manifest where both declaration fields are absent. If either field is present, both must be valid. This preserves restart/rollback of historical last-known-good generations while ensuring newly strict-applied generations are provenance-bound.

## Consequence

A future declaration compiler coordinator can now:

1. read exact declaration revision N;
2. verify its stored SHA-256;
3. compile deterministic native artifacts;
4. bind `(N, declaration_sha256)`;
5. enter `ApplyNativeArtifact`.

After this ADR, a persisted strict generation can be traced back to exact declaration bytes without overloading `daemon_state.config_revision`.
