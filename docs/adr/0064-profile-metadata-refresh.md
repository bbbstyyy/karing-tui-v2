# ADR 0064: Metadata-only profile refresh is isolated and bounded

## Status

Accepted.

## Context

Karing exposes subscription traffic/quota/expiry as UI state and the fixed public application source shows a separate HTTP HEAD traffic-refresh path.

The project already parsed `Subscription-Userinfo` during full profile fetches, but a TUI traffic refresh must not download the full subscription, replace node snapshots, increment normal refresh failure counters, or allow an older in-flight HEAD response to overwrite metadata obtained by a newer refresh.

The same profile source can also be edited or fully refreshed while metadata is being fetched. A metadata endpoint therefore needs source identity/revision ownership and explicit concurrency limits, not just an HTTP helper.

## Decision

The daemon exposes:

```text
GET  /v1/profiles/{profile_id}/metadata
POST /v1/profiles/{profile_id}/metadata/refresh
```

The POST body carries `expected_source_revision`. The refresh:

1. reads and validates the enabled ProfileSource at that exact revision;
2. reuses `profilefetch.SourceFetcher.FetchMetadata`, so Direct/Selected routing and the five-second metadata timeout ceiling are identical to the existing fetch stack;
3. performs an HTTP HEAD only;
4. records a UTC observation time after the response is received;
5. commits through a storage transaction that rechecks source revision, refuses an active full-update lease, and accepts only a strictly newer observation time;
6. preserves the accepted node snapshot and all normal full-refresh health/backoff fields.

A response without `Subscription-Userinfo` is a no-op. A valid header replaces structured usage and clears the metadata error. A malformed observed header advances the metadata observation/error state but retains the last-known-good usage and its timestamp.

Source identity changes clear both usage state and metadata observation time. A stale HEAD response using the prior source revision therefore cannot attach metadata to the new source.

## Concurrency

The daemon admits at most four metadata refresh requests at once and at most one per ProfileID. Additional requests fail immediately with HTTP 429 and `Retry-After: 1`.

This admission budget is independent of the scheduled full-refresh worker budget. Storage remains the final correctness boundary: if a full profile update starts while a HEAD request is in flight, the metadata commit fails closed rather than racing the snapshot transaction.

## API ownership

The GET endpoint reads only persisted daemon state. The internal client exposes typed GET/refresh methods; future TUI code must use these daemon APIs rather than opening SQLite or issuing an independent provider request.

## Failure semantics

Provider/network/timeout/HTTP errors are returned to the caller but do not:

- advance `last_attempt_at` or `last_success_at`;
- increment `consecutive_failures`;
- set normal profile refresh backoff;
- replace or invalidate the current node snapshot.

This keeps an optional traffic-display request from degrading subscription availability.

## Validation

Tests cover:

- schema-v15 migration;
- valid metadata-only persistence;
- malformed metadata preserving last-good usage;
- monotonic observation ordering;
- source-revision conflict;
- refusal during an active full update;
- provider failure isolation from full-refresh health;
- HTTP HEAD behavior through the daemon route;
- GET visibility of persisted metadata;
- four-request global admission and same-profile non-reentry.

## Consequences

M3 now has a bounded Karing-like traffic metadata refresh path without creating a second network policy stack or coupling optional provider metadata to node refresh health.

Specific Node fetch execution remains a separate unsupported capability and continues to fail closed.
