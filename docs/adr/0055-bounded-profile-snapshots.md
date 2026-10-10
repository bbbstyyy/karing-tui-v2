# ADR 0055: Profile updates use bounded immutable snapshots

## Status

Accepted.

## Context

M3 subscription/profile updates must not overwrite the only valid node state while a source is being downloaded or parsed. The plan requires empty, corrupt, partial and unexpectedly changed updates to be isolated, with the existing valid snapshot remaining usable.

Profile node identity is already defined by ADR 0054 as a stable mapping from `(profile ID, source key)` to project NodeID. That identity still needs a durable update boundary. A mutable node table would make partial writes and update failures harder to distinguish from a committed source revision, while retaining every successful update forever would violate the project's bounded-storage requirement.

## Decision

SQLite schema v9 adds three tables:

- `profile_snapshots`: immutable accepted source revisions and their source SHA-256;
- `profile_snapshot_nodes`: ordered stable node identities for one snapshot;
- `profile_state`: the current and immediately previous accepted snapshot for each profile.

A profile update is committed in one SQLite transaction:

1. validate profile/source metadata before writing;
2. load the current accepted snapshot;
3. reconcile incoming source keys through the ADR 0054 identity rules;
4. insert a new immutable snapshot and its ordered nodes;
5. atomically move `current_snapshot_id` to the new snapshot and the former current snapshot to `previous_snapshot_id`;
6. prune every older snapshot for that profile.

The store therefore retains at most two successful snapshots per profile. This is intentionally separate from configuration generations: profile snapshots describe imported source state, while config generations describe an exact compiled runtime.

An empty incoming node set is rejected by default. A caller must explicitly set `AllowEmpty` to accept a successful empty profile. This keeps an HTML error page, parser regression or temporarily empty subscription from silently erasing the current usable profile.

Invalid reconciliation, duplicate source keys or invalid metadata abort the transaction and leave the current pointer unchanged.

## Source metadata

Each accepted snapshot records:

- stable profile ID;
- source kind;
- optional source revision marker such as an importer-owned version/ETag representation;
- mandatory 32-byte source SHA-256 encoded as 64 hexadecimal characters;
- acceptance timestamp.

The source digest identifies the downloaded/imported input, not the runtime configuration. Importers remain responsible for calculating it over a documented byte representation.

## Scope

The snapshot currently persists the source identity layer required for safe node reconciliation and dynamic group membership. Protocol payload persistence, user overlays, fetch attempt history, traffic metadata and scheduling are separate M3 slices.

Subscription-provided routing remains outside this model. A profile snapshot cannot create a routing layer, MATCH/FINAL rule, ISP rule or rule-provider binding. Importers may report ignored routing content, but it does not enter the five-layer runtime routing tree.

## Validation

Tests cover:

- stable NodeID preservation for unchanged source keys;
- explicit rename reporting;
- same-name nodes with changed source keys becoming remove+add;
- atomic rejection of duplicate source keys;
- empty-source refusal unless explicitly confirmed;
- persistence across database reopen;
- migration from schema v8 to v9;
- retention of only current + previous successful snapshots.

## Consequences

The first M3 persistence boundary is now crash-safe and storage-bounded. A future subscription worker can stage download/parse work outside SQLite, then perform one short commit only after the complete candidate has passed importer validation.

The next slice should persist normalized node payload/compatibility diagnostics and connect a concrete importer to this snapshot boundary. Dynamic custom URLTest behavior must remain blocked until the missing Karing runtime-builder semantics for saved `regexs` are verified; the public UI alone only proves their candidate-search behavior.
