# ADR 0060: Subscription usage metadata is optional last-known-good state

## Status

Accepted.

## Context

M3 requires profile traffic/quota/expiry metadata without allowing optional provider metadata to destabilize the node update path.

The fixed Karing application snapshot proves that remote profile traffic is a first-class UI/state concept and that Karing has a separate traffic refresh path using an HTTP HEAD request before passing response headers to `ProxyConfUtils.getTraffic`. The implementation of `ProxyConfUtils.getTraffic` is not present in the fixed public source tree, so its exact parsing behavior cannot be treated as a verified compatibility contract.

A common interoperable source is the `Subscription-Userinfo` response header carrying semicolon-separated `upload`, `download`, `total` and `expire` fields.

## Decision

The project implements a bounded, explicit parser for `Subscription-Userinfo`.

Recognized fields are:

- `upload`: non-negative decimal bytes;
- `download`: non-negative decimal bytes;
- `total`: non-negative decimal bytes;
- `expire`: non-negative Unix seconds; zero means no known expiry.

Unknown fields are ignored so provider extensions do not make an otherwise valid header unusable. Duplicate recognized keys, malformed integers, control characters, invalid UTF-8, unsupported expiry range and headers larger than 4096 bytes produce a metadata diagnostic.

The parser does not infer remaining quota or enforce `upload + download <= total`; providers can legitimately report over-quota states or use `total=0` with provider-specific meaning.

## Refresh behavior

A valid usage header is attached to the fetch result and committed with profile update success metadata.

A malformed usage header does **not** fail the source fetch, node compatibility analysis or accepted snapshot transaction. Instead:

1. the node/profile refresh continues normally;
2. the malformed-header diagnostic is persisted as the latest metadata error;
3. the previous valid usage/quota/expiry values and their timestamp remain unchanged.

If the response does not carry `Subscription-Userinfo`, the prior usage metadata is also preserved. This prevents a transient provider/header change from erasing information that was previously valid.

A later valid header replaces the complete structured usage value and clears the metadata error.

HTTP 304 responses may refresh usage metadata if the server includes the header while keeping the accepted profile snapshot unchanged.

## Source revision ownership

Fetch validators and usage metadata belong to a specific ProfileSource identity.

Changing source format, URL/path, User-Agent or fetch path resets:

- last attempt/success/error;
- source revision marker;
- ETag and Last-Modified;
- failure/backoff state;
- subscription usage/quota/expiry and metadata diagnostic.

Changing only enabled state or update interval does not reset these values.

The current accepted profile snapshot is deliberately retained across a source identity edit. It remains the last usable state until the newly configured source produces a complete accepted replacement.

## Persistence

SQLite schema v12 adds bounded nullable columns on the single `profile_sources` row:

- upload bytes;
- download bytes;
- total bytes;
- expiry timestamp;
- usage metadata update timestamp;
- latest metadata diagnostic.

There is no per-refresh usage history table, so this feature does not introduce unbounded storage growth.

## Validation

Tests cover:

- valid upload/download/total/expire parsing;
- zero expiry;
- unknown extension fields;
- duplicate/malformed/control-character/oversized metadata;
- HTTP capture of valid metadata;
- malformed HTTP metadata not failing body fetch;
- persistence of valid usage and expiry;
- preservation of last-good usage after malformed metadata;
- end-to-end node refresh succeeding while a malformed usage header is recorded;
- source identity edits clearing validators/usage while retaining the last usable snapshot.

## Consequences

M3 now has a durable traffic/quota/expiry foundation without coupling optional provider metadata to node availability.

A dedicated manual HEAD-only traffic refresh endpoint may be added later if the TUI needs Karing-like metadata refresh without downloading the full subscription body. That feature must reuse the same explicit Direct/Selected network path and metadata parser rather than creating another hidden HTTP stack.
