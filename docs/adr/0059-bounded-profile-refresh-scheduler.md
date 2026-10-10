# ADR 0059: Profile refreshes are bounded, conditional and staggered

## Status

Accepted.

## Context

M3 requires long-running subscription refresh without turning transient network failure into repeated writes, request storms or loss of the last usable profile.

The fixed Karing application snapshot confirms a per-profile update interval model. New remote profiles default to 12 hours, the editor clamps configured intervals to a minimum of 5 minutes and a maximum of 365 days, and a null/disabled interval turns automatic refresh off. Karing also uses a global subscription-update guard in addition to per-profile reload tracking.

This project needs the same user-visible scheduling capability, but with stronger durable failure isolation, conditional HTTP state and explicit concurrency budgets.

## Decision

### Refresh pipeline

All automatic and manual refresh execution uses the same coordinator:

```text
acquire (profile, source revision) lease
  -> read source spec while lease prevents mutation
  -> fetch outside database write transactions
  -> decode/analyze outside database write transactions
  -> atomically commit accepted profile snapshot + update-success metadata
```

A source configuration revision is acquired before the source URL/path is read. This prevents a worker from holding a lease for a new revision while accidentally using an old source specification.

If fetching, decoding, compatibility analysis or snapshot validation fails, the current accepted snapshot remains unchanged and the lease is completed as a failure.

### Conditional HTTP

Remote HTTP/HTTPS refresh:

- never inherits `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY`;
- uses the explicit Direct or Selected fetch policy only;
- sends persisted ETag and Last-Modified validators;
- accepts HTTP 304 only when an accepted snapshot already exists;
- stores ETag/Last-Modified on success;
- stores Retry-After from error responses when available;
- limits body size, redirects, response headers and total request duration.

The current Selected implementation is an HTTP proxy connection to an explicitly supplied loopback mixed inbound. Specific Node fetching remains unsupported until an exact user-space detour path is implemented; it must fail closed rather than silently becoming Direct.

### Local files

Linux local-file refresh opens the final path with `O_NOFOLLOW`, requires a regular file and applies the same bounded body limit. File content is versioned with its source SHA-256.

Local files are currently manual-refresh inputs. Automatic polling is restricted to URL sources.

### Source update interval

`ProfileSource.UpdateInterval` is persisted as whole seconds:

- `0`: automatic refresh disabled;
- minimum: 5 minutes;
- default for newly configured remote profiles: 12 hours at the product/UI layer;
- maximum: 365 days.

The storage/model layer does not silently turn `0` into 12 hours. Callers that want the Karing-compatible default must explicitly set `DefaultUpdateInterval` when creating a remote profile.

### Scheduling

The scheduler is a single owner with two independent concurrency boundaries:

1. the durable update lease prevents the same profile from refreshing concurrently;
2. an in-memory semaphore limits global refresh concurrency.

Defaults:

- scan interval: 30 seconds;
- global concurrent refreshes: 2;
- hard supported concurrency ceiling: 16;
- daemon-start overdue spread window: 2 minutes;
- failure backoff base: 1 minute;
- failure backoff ceiling: 1 hour.

A never-attempted or already-overdue profile is deterministically spread inside the startup window instead of all firing as the daemon starts.

Transient failures use bounded exponential backoff with stable 80%-120% per-profile jitter. Persisted server Retry-After is a lower bound and overrides an earlier local retry time.

Stable jitter is derived from profile ID and failure count. It deliberately remains stable across repeated scheduler scans and daemon restarts; this prevents a profile's eligibility time from moving every time the scheduler evaluates it while still de-correlating large source sets.

Manual refresh is not blocked by scheduler backoff. It must still acquire the same durable source-revision lease.

### Cancellation and lifecycle

Scheduler workers share the daemon context. On cancellation:

- no new work is dispatched;
- active workers observe the same context;
- the scheduler waits for dispatched workers to exit before returning.

Per-profile fetch/import/network errors are persisted by the refresh coordinator and do not terminate the scheduler. Scheduler infrastructure errors such as an unreadable authoritative source table are returned to the daemon for explicit handling.

### Runtime application boundary

A successful scheduled refresh changes the accepted profile snapshot only.

It does **not** automatically mutate the current declaration or apply a new runtime generation. Snapshot-to-declaration impact checking, declaration CAS, compile and managed apply remain separate boundaries under ADR 0057. Automatic application policy must be designed explicitly rather than inferred from download success.

## Validation

Tests cover:

- conditional GET followed by 304 without a new snapshot;
- refusal of 304 when no accepted snapshot exists;
- HTTP 429/Retry-After while retaining the previous snapshot;
- unsupported imported protocol while retaining the previous snapshot;
- local-file source SHA revisions and stable NodeID reconciliation;
- same-profile refresh non-reentry;
- source-revision locking before source-spec use;
- confirmed interval bounds and schedule persistence;
- deterministic startup staggering;
- bounded exponential failure retry;
- Retry-After dominance;
- global scheduler concurrency;
- no duplicate in-memory dispatch of one profile;
- scheduler cancellation waiting for workers.

## Consequences

The refresh subsystem is now suitable for daemon ownership without requiring network I/O inside SQLite transactions or unbounded background workers.

Before daemon auto-refresh is enabled, its Selected fetch proxy must be derived from the same authoritative inbound configuration used by the managed core. It must not be independently hard-coded.
