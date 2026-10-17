# ADR 0054: Profile-owned source keys define stable node identity

## Status

Accepted.

## Context

M3 requires subscription/profile updates to preserve user state while M2 still needs Karing-compatible custom URLTest groups whose explicit members and future dynamic filters can span multiple subscriptions.

The fixed Karing UI snapshot shows that a custom URLTest stores two different inputs:

- explicit selected server `tag` values;
- separate `regexs` search/filter expressions.

The project cannot safely implement either behavior by treating a display name as a globally unique node identity. Across multiple profiles, names collide. During updates, an upstream rename may also make identity ambiguous. The plan explicitly forbids silently choosing another same-name node when a unique mapping is lost.

At the same time, older or imported project state may already carry a valid project-owned NodeID that is not derived by the new algorithm. Reconciliation must not rewrite such an ID merely because a deterministic derivation is now available.

## Decision

Introduce `internal/profile` with an evidence-bounded identity contract.

Each importer must produce a profile-local `SourceKey` for every parsed node. The key is an exact source identity chosen by that importer from the strongest identity the format actually provides. Examples include an outbound tag in a tagged native format, or the proxy name when that format itself uses the name as its only key.

The profile reconciliation layer then owns the mapping:

```text
(profile ID, source key) -> project NodeID
```

Rules:

1. If a source key already exists in the previous snapshot, preserve its existing NodeID exactly.
2. A source-name/display-name change under the same source key is reported as a rename and keeps the NodeID.
3. A changed source key is remove+add, even when the display name is identical.
4. New nodes receive a deterministic project NodeID derived from profile ID + source key with a versioned SHA-256 domain separator.
5. Duplicate source keys, cross-profile prior identities, control characters and NodeID collisions fail closed.
6. Output order follows the incoming source snapshot. Removed-node reporting follows prior order.

No fuzzy matching, same-name fallback, credential-based guessing or endpoint-based guessing is performed here.

This makes future user overlays (alias, favorite, ordering, selection preference), fixed-node routing targets and URLTest membership anchor to NodeID instead of display text.

## Importer obligations

`SourceKey` is format-specific evidence, not a universal hash of `server:port`.

Importers must document their key choice in the compatibility matrix and must not silently change the algorithm between releases. If a source format has no identity stronger than a mutable name, a rename is intentionally observed as remove+add and the impact analysis must say so.

The layer deliberately does not canonicalize unknown protocol fields yet. Protocol materialization remains owned by importers and the node model.

## Dynamic URLTest consequence

This ADR does not yet implement regex expansion. It establishes the identity boundary needed for it:

- explicit Karing tags can be resolved by an importer/profile snapshot to stable NodeIDs;
- regex results can be expanded to stable NodeIDs at declaration/update time;
- ambiguous or missing mappings can be diagnosed without binding by display name.

Regex syntax, matching field, enabled-profile scope, merge/dedup order and processing budgets still require their own compatibility fixture before M2 can claim full dynamic URLTest parity.

## Validation

Unit tests verify deterministic new IDs, migration-safe preservation of prior IDs, rename reporting, incoming-order preservation, removals, duplicate-key rejection and the critical no-same-name-rebind rule.

## Consequences

M3 profile identity can now be built independently of individual subscription formats, and M2 custom URLTest work can depend on a stable cross-profile node identity instead of runtime outbound tags.

This does not yet claim subscription import, scheduling, node payload reconciliation, user overlay persistence or dynamic regex compatibility.
