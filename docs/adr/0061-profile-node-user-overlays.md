# ADR 0061: Profile node user state is a stable-ID overlay

## Status

Accepted.

## Context

M3 requires subscription refreshes to preserve user state. The fixed Karing application snapshot keeps user-level server state separately from subscription source data: its `ServerUse` state contains disabled servers, recent servers and favorites. Karing's disable key is based on protocol/server/port, while this project already owns a stronger stable identity `(ProfileID, NodeID)`.

Subscription snapshots are immutable source truth. User choices such as disabling a node, pinning it as a favorite, assigning a local alias or changing display/runtime ordering must not be rewritten into source payloads and must not disappear when a subscription refresh changes protocol fields or source display names.

## Decision

Node user state is stored in a separate `profile_node_overlays` table keyed by `(profile_id, node_id)`.

The current overlay model contains:

- `Disabled`;
- `Favorite`;
- `Alias`;
- optional `SortRank`.

Each overlay row has its own monotonically increasing revision and is updated through compare-and-swap.

A new overlay can only be created for a node present in the current accepted snapshot. Existing overlay rows are not deleted when a node disappears from a later snapshot. If the same stable NodeID returns, the user state becomes effective again.

This is intentional: source disappearance can be temporary, and deleting user state during refresh would violate the M3 requirement that subscription updates do not destroy user choices.

To bound storage, a profile can retain at most 8192 overlay rows. Hitting the limit fails closed instead of silently deleting older user state.

## Runtime boundary

Only runtime-relevant overlay fields affect declaration materialization:

- `Disabled` removes the node from the effective node set;
- `SortRank` deterministically reorders nodes.

`Favorite` and `Alias` are UI/user metadata and do not change core configuration.

Runtime-relevant overlays are canonicalized and hashed. Snapshot-to-declaration commits include the overlay SHA-256 in declaration provenance:

`profile-snapshot/<snapshot-id>/overlay/<sha256>`

This makes a declaration revision explicitly dependent on both the immutable source snapshot and the user runtime overlay state. The compiler still consumes a fixed declaration revision and does not query mutable overlay tables.

If disabling a node would leave an existing declaration with an invalid required reference, declaration replacement fails closed and does not advance the current declaration.

## Ordering

Nodes with explicit SortRank are ordered first by ascending rank. Ties preserve source snapshot order. Nodes without a rank preserve source snapshot order after explicitly ranked nodes.

No ordering depends on Go map iteration.

## Non-runtime user state

Alias and favorite state are persisted now so later TUI work does not need to retrofit a second identity mechanism. They are deliberately excluded from runtime overlay hashes because changing them must not force a semantically identical core generation.

Recent-use history is not included in this table; it is observational/user-navigation state and will be modeled separately if required.

## Validation

Tests cover:

- overlay field validation and bounded aliases/ranks;
- CAS creation and updates;
- refusal to create overlays for unavailable nodes;
- stable listing order;
- bounded retained overlay rows;
- preservation across source snapshot refresh and removal;
- disabled-node fail-closed declaration replacement;
- deterministic SortRank application;
- declaration provenance binding to the runtime overlay digest.

## Consequences

Subscription refresh can now replace source payloads without overwriting disabled/favorite/alias/order user state.

A future profile filter model remains separate. Subscription-wide filtering determines which source nodes are accepted into the effective profile; per-node overlays represent explicit user state attached to already reconciled stable node identities.
