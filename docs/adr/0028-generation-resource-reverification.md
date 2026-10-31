# ADR 0028: Re-verify persisted generation resources before every core transition

- Status: Accepted
- Date: 2026-10-06

## Context

Persisting a manifest beside a generation is only useful if runtime transitions trust it instead of assuming referenced files remain intact forever.

Rule-set files live in a private content-addressed store, but disk corruption, accidental modification by the same UID, restore mistakes, or manual edits can still make a persisted generation inconsistent after it was originally compiled.

A restart or rollback is especially sensitive: it may happen long after the original apply transaction and must not start a core against a partially damaged generation.

## Decision

When a generation has schema-v3 compiler metadata, ManagedCore verifies the complete persisted identity before:

- candidate `check`;
- explicit core start;
- candidate activation;
- rollback to a previous generation.

The common verification gate checks:

1. candidate config SHA-256 matches the generation row;
2. candidate config bytes equal the persisted config bytes;
3. manifest and source-map bytes match their persisted SHA-256 values;
4. source-map JSON is valid;
5. manifest decodes as the current `compiler.NativeManifest`;
6. manifest schema ID equals the exact native compiler/core schema ID;
7. manifest config SHA-256 equals the generation config SHA-256;
8. each rule-set path is content-addressed by the recorded hash and expected extension;
9. each private rule-set file passes `coreartifact.VerifyRuleSet`.

Only after this gate may config staging, core `check`, binding, or process restart occur.

## Compatibility

A generation with all metadata fields absent is treated as a legacy generation and remains usable.

A generation with only some metadata fields present is treated as corrupt/incomplete and is rejected.

A storage implementation that predates `GenerationArtifacts` retains the old behavior; production SQLite schema v3 implements the strict interface.

## Failure behavior

Verification is fail-closed.

A damaged rule-set, manifest hash mismatch, unsupported schema ID, or config mismatch prevents the core transition. The verifier never repairs files in place and never substitutes another resource version.

This keeps rollback semantic identity tied to the exact compiled generation rather than merely to the native config filename.

## Remaining work

- verify persisted source-map structure beyond JSON syntax;
- include declaration revision/source identity and compiler diagnostics in the generation metadata contract;
- add corruption/restart integration fixtures using the real approved core;
- define retention/garbage collection so content-addressed resources still referenced by any retained generation cannot be deleted.
