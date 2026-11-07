# ADR 0062: Persist Karing profile-filter state before enabling filter execution

## Status

Accepted.

## Context

M3 requires subscription node filtering, but compatibility must not be inferred from UI labels alone.

The fixed Karing application snapshot exposes a `ProxyFilter` editor with three methods (`all`, `include`, `exclude`), a `keywordOrRegx` value and a `matchAttribute` switch. The same filter object and a separate removed-tag list are passed back into subscription reload.

The actual filter implementation is provided by Karing's external `vpn-service` dependency, which is not present in the fixed public application source tree used by this project. Therefore the exact expression grammar, regex/keyword decision rule and attribute matching semantics are not currently verifiable from the pinned application source.

## Decision

The project persists the verified filter configuration shape now, while keeping filter execution disabled until its semantics are proven.

`ProfileSource` contains a `NodeFilterSpec` with:

- method: all/include/exclude;
- keyword-or-regex expression;
- match-attribute flag.

Internally the zero method value represents `all` so existing zero-value source specifications remain valid.

Filter expressions are bounded to 4096 bytes, must be trimmed valid UTF-8 and may not contain control characters. This is a persistence/input safety boundary, not an interpretation of Karing's expression language.

SQLite schema v14 stores the filter state on the revisioned `profile_sources` row. Filter edits therefore use the same ProfileSource CAS and cannot race an active refresh worker.

## Runtime boundary

Persisted filter state is **not** applied to imported nodes yet.

Daemon capabilities distinguish:

- `profile_node_filter_state = true`;
- `profile_node_filter = false`.

This prevents TUI or API clients from treating stored configuration as active behavior.

No refresh, snapshot or declaration code is allowed to silently interpret `keywordOrRegx` until exact behavior is supported by evidence and regression fixtures.

## Validation

Tests cover:

- all/include/exclude state validation;
- bounded and terminal-safe expression storage;
- ProfileSource validation;
- CAS persistence;
- reopen persistence;
- schema migration to v14;
- capability reporting that separates persisted state from active execution.

## Consequences

The project can preserve user filter configuration without inventing semantics.

Once the pinned `vpn-service` implementation or equivalent authoritative behavior is available, filter execution can be added behind a new compatibility fixture without another storage migration. At that point filter edits must trigger deterministic re-materialization of the source snapshot rather than waiting for an unrelated future refresh.
