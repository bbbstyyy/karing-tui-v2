# ADR 0057: Profile snapshots enter runtime through explicit declaration revisions

## Status

Accepted.

## Context

The plan requires deterministic compilation: the compiler must not read a mutable "latest subscription" while building a runtime generation. At the same time, M3 profile updates need a path to change imported node payloads without rewriting user routing, DNS and selection intent by hand.

Declaration v1 currently stores node materialization inline. That is sufficient for deterministic compilation, but a profile update needs a controlled way to replace only one profile's nodes and determine whether removals invalidate existing stable references.

Reading `profile_state.current_snapshot_id` from inside the compiler would violate the explicit-revision rule because the same declaration revision could compile differently after a background subscription update.

## Decision

Profile updates and runtime declarations remain separate transactions.

A caller first selects an exact retained profile `snapshot_id`. The daemon-side coordinator then:

1. loads that exact snapshot by `(profile_id, snapshot_id)`;
2. verifies its stored node payload hashes;
3. materializes domain nodes from the persisted, already compatibility-checked payload;
4. replaces that profile's inline nodes in a copy of a specific declaration v1 document;
5. computes an impact report of added, removed and retained NodeIDs;
6. validates the complete candidate declaration, including all SelectionGroup and routing references;
7. commits the candidate with declaration revision CAS only if validation succeeds.

The committed declaration source records `profile-snapshot/<snapshot_id>`. The globally unique SQLite snapshot ID gives an audit link without putting arbitrary profile names into the restricted source string.

The compiler continues to consume only the immutable declaration revision. It never follows the profile's mutable current pointer.

## Fail-closed reference behavior

A source-key change produces a new NodeID under ADR 0054. If the removed NodeID is still referenced by CurrentSelected, a URLTest, a Specific Node routing target or another declaration object, `ReplaceProfileNodesV1` returns an inspectable candidate and impact report but marks the replacement invalid.

The current declaration revision remains unchanged.

There is no same-name substitution, automatic fallback to another node, automatic removal from selection groups or DIRECT fallback.

An unreferenced profile can be removed by replacing it with an explicitly accepted empty snapshot; normal profile import still requires explicit empty confirmation under ADR 0055.

## Ordering

Replacing one profile preserves the relative order of every other declaration node. Replacement nodes use the exact order from the selected profile snapshot and are inserted at the first prior position of that profile, or appended when the profile was not previously present.

This keeps candidate order deterministic while allowing one profile's source order to change explicitly.

## Initial configuration

This mechanism requires an existing declaration revision because a profile snapshot contains nodes, not the complete routing/DNS/selection declaration.

Initial setup remains a separate configuration/bootstrap workflow. The profile updater must not invent FINAL, DNS or CurrentSelected defaults merely to make an imported subscription runnable.

## Validation

Tests verify:

- payload changes under the same source key preserve NodeID and update the declaration node payload;
- exact snapshot ID is recorded in declaration provenance;
- a removed referenced node produces added/removed impact but no declaration commit;
- unreferenced profiles can be removed;
- cross-profile replacement inputs are rejected;
- declaration revision CAS remains the final write boundary.

## Consequences

Subscription refresh can now be decomposed safely into:

```text
fetch/parse -> accepted profile snapshot
            -> user/automation evaluates impact
            -> exact snapshot + expected declaration revision
            -> declaration candidate
            -> declaration commit
            -> normal compile/apply transaction
```

A successful profile download alone does not alter the running proxy. This is intentional: runtime changes still pass through declaration validation and the existing managed apply/rollback path.

Future scheduling can automate these steps only under an explicit update policy; it must retain the same snapshot/declaration/apply boundaries.
