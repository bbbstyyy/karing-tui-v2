# ADR 0031: Apply CN user changes as a typed overlay over the immutable snapshot

- Status: Accepted
- Date: 2026-10-06

## Context

The CN preset must initialize user-visible defaults without becoming mutable source data. Restart, subscription update, or application upgrade must not copy the six upstream default switches back over user choices.

The project also needs to let a user redirect a preset group to CurrentSelected, a custom URLTest group, or a fixed node, and bind group DNS independently, while preserving the exact upstream match material for diagnostics and future compatibility conversion.

## Decision

CN user state is represented as an overlay keyed by the project-owned stable group ID.

A `CNOverride` may change only:

- `Enabled`;
- typed `TargetRef`;
- optional `DNSProfileID`.

It cannot change:

- source ordinal;
- display name or emoji;
- rule-set/domain/IP/package/process source fields.

`ApplyCNOverrides` creates an effective view by deep-copying the immutable snapshot and applying the overlay in place without reordering groups.

## Validation

The overlay layer rejects:

- unknown group IDs;
- duplicate overrides for the same group;
- empty group IDs;
- invalid typed targets;
- DNS profile identifiers with padding, unsupported characters, or excessive length.

An explicit empty DNS profile value clears a binding. A nil field means "leave the current snapshot/user value unchanged".

## Persistence consequence

Future declaration storage should persist the overlay, not a rewritten copy of the upstream CN JSON.

That gives preset upgrades a clean three-way input:

1. old immutable upstream snapshot;
2. new immutable upstream snapshot;
3. user overlay keyed by stable project group ID.

A future upgrade preview can then distinguish upstream rule/name/order changes from actual user choices instead of trying to diff one mutated blob.

## Compiler boundary

This overlay still does not translate the flat Karing condition fields into `MatchExpr`. It only resolves the mutable binding state that will be attached after compatibility conversion.

Therefore `cn_preset_overrides=true` does not imply `cn_preset=true`.
