# ADR 0058: Profile sources use revisioned configuration and crash-safe update leases

## Status

Accepted.

## Context

M3 requires scheduled subscription/profile updates, but network work must not run inside SQLite write transactions and repeated/manual/scheduled refreshes must not overlap for the same source.

The update path also needs durable conditional-request and retry state. Keeping this only in an in-memory scheduler would lose ETag/Last-Modified and failure history across daemon restarts, while keeping an unbounded per-attempt table would conflict with the project's storage-budget rules before operator-facing retention is designed.

Profile source configuration can change while a scheduler is alive. A worker created from an older URL/fetch policy must not later report success against a newly edited source.

## Decision

SQLite schema v10 adds one bounded `profile_sources` row per profile.

Revisioned source configuration includes:

- source format;
- location kind and location;
- explicit User-Agent;
- fetch policy;
- enabled state.

The first supported source format is native sing-box. Locations are either an HTTP/HTTPS URL or an absolute clean local file path.

Fetch policy is typed as:

- Direct;
- CurrentSelected;
- Specific Node identified by stable `(ProfileID, NodeID)`.

A local file source must use Direct mode. Network implementation for a declared mode remains capability-gated; modelling a policy does not claim that its downloader has already been implemented.

Each source configuration has a monotonically increasing revision and is updated by CAS. Source configuration cannot be mutated while an update lease is active.

## Update lease

Before doing any file/network I/O, a worker acquires:

```text
(profile_id, expected_source_revision, update_id)
```

Only one active lease may exist for a profile. Active update IDs are also globally unique in the database.

The lease records the exact source revision and start time. Completion requires the same profile ID, source revision and update ID, so a stale worker cannot complete against a different source configuration.

A successful completion stores:

- last attempt/success time;
- importer/source revision marker;
- ETag;
- Last-Modified;
- resets consecutive failures and Retry-After state.

A failed completion stores:

- bounded terminal-safe error text;
- increments consecutive failures;
- optional Retry-After timestamp;
- leaves the last successful source metadata intact.

The database does not enforce sleep/backoff timing itself. Scheduler policy will interpret consecutive failures and Retry-After, so an explicit operator action can later have a separately designed bypass policy without weakening lease ownership.

## Crash recovery

An active lease survives a process crash. On daemon startup, all such leases are marked interrupted before new work is scheduled:

- active update ID/start time are cleared;
- `last_error` becomes `daemon restarted during profile update`;
- consecutive failure count increments;
- the prior successful snapshot remains authoritative.

The daemon performs this recovery alongside apply-journal recovery before starting runtime background work.

## Source-location confidentiality

Subscription URLs may contain query tokens. The authoritative store may persist the location because refresh needs it, but normal status/log/error surfaces must not echo the raw location. Future API/TUI responses need a redacted source view.

HTTP userinfo is rejected entirely.

## No network I/O in SQLite transactions

The lease transaction is deliberately short:

```text
acquire lease -> commit DB
              -> fetch/read outside transaction
              -> parse/analyze outside transaction
              -> accepted snapshot/declaration transaction
              -> complete lease
```

A later coordinator should tighten accepted snapshot + lease-success state into one atomic database boundary where useful, but it must not hold a write transaction across network or parser work.

## Bounded state

Schema v10 keeps only current source configuration and latest outcome metadata. It does not add an unbounded attempt-history table.

Long-term user-visible job history, if added, requires an explicit retention/quota ADR.

## Validation

Tests cover:

- source configuration create/update CAS;
- CurrentSelected and Specific Node fetch-policy validation;
- safe URL/file location validation;
- current snapshot linkage;
- same-profile update non-reentry;
- source-edit refusal during an active lease;
- disabled/stale source rejection;
- failure metadata and Retry-After;
- ETag/Last-Modified success metadata;
- stale lease completion refusal;
- terminal-safe update IDs/error text;
- persisted active lease recovery after database reopen.

## Consequences

The daemon now has durable scheduling ownership without yet performing external network I/O.

The next slice can implement a bounded fetcher that explicitly refuses environment proxies, honors ETag/Last-Modified and redirect/body/time budgets, and maps Retry-After into this state. It must fail closed for fetch modes it cannot actually realize.
