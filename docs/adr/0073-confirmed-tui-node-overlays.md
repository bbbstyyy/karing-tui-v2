# ADR 0073: Explicitly confirmed TUI node overlay mutations

## Status

Accepted as an incremental M4 client-only feature. This does not complete the TUI or M3 routing/DNS compatibility.

## Context

ADR 0072 provides a read-only Bubble Tea profile/node browser. The daemon already owns a revisioned, per-node full overlay replacement API. Sending partial or default-filled updates from a TUI can silently erase alias/sort preferences; optimistic display updates can falsely report success when an HTTP request timed out after being committed.

## Decision

On the Nodes page, **f** proposes a favorite toggle and **d** proposes a disabled toggle for the currently selected **stable NodeID**. Neither key writes. A **y** confirmation sends a single bounded 10-second daemon request; **Esc** cancels the proposal without a write. All other navigation is blocked while confirming or writing, except **q/Ctrl-C** to exit the disposable TUI. If the TUI exits while a request is in flight, the daemon may still commit it; terminal cancellation must not be described as rollback.

The request contains the **complete** snapshot-observed disabled/favorite/alias/sort-rank state plus the exact node-overlay revision CAS. Other fields are preserved byte-for-byte and never replaced with defaults. Nodes without an accepted snapshot are not writable. The TUI uses the existing Unix-socket `PUT /v1/profiles/{profile}/nodes/{node}/overlay` endpoint; it never writes SQLite itself.

After either a success or an ambiguous error, the node page is re-fetched; an error is **not** presented as a failed/no-op write, because the server may have accepted the mutation before the connection failed. Errors and returned untrusted strings are not printed. Stale write completions and late read responses cannot replace newer state. Saved overlays do **not** advance a declaration revision, apply a core generation, or restart the core. In particular disabling a profile node here is not a promise that already-applied traffic will move elsewhere; profile-to-declaration staging remains a separate, guarded operation.

There is deliberately no timer-driven background refresh, automatic retry, multi-node bulk operation, alias editing, or implicit profile refresh.

## Verification

TUI tests exercise cancellation/no-write, confirmation, stable row selection, full-field/CAS preservation, single in-flight write, post-write read-back, secret-bearing errors, stale responses, and missing-snapshot refusal. CI retains format, vet, unit/race tests and managed-core integration. This slice does not change the five-source routing order or import subscription/ISP rules.

## Open follow-up

Add user-confirmed current-selection mutations and controlled diagnostics. ADR 0074 provides a bounded applied-generation route/DNS-binding probe but is not a complete DNS observation UI. Continue M3 per-field import/protocol compatibility and CN offline resource/license closure as explicit release blockers.
