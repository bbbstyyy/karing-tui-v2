# ADR 0245: explicit TUI snapshot-to-declaration stage after source refresh

Status: MVP-1A / MVP-3 partial, Pre-MVP. Not full MV-02/MV-05 or MVP Beta acceptance.

## Decision

The existing Profiles view gains "b: stage snapshot" for an already created
declaration and an enabled source with a complete, accepted current snapshot.
First-run users must continue to use the separate Nodes "i" wizard with an
explicit resolver and proxy-only/no-CN acknowledgement. The snapshot binding
operation never creates a declaration from zero, alters routing layers, or
implicitly selects or activates nodes.

The TUI invokes the existing protected per-profile declaration Preview and
Stage endpoints only, without reconstructing a declaration or handling native
Core JSON. A read-only preview binds an accepted immutable snapshot and base
declaration revision, confirms source revision, validates bounded numeric
added/removed/retained node counts and stable-ID sample structure, checks both
SHA-256 digests, and projects only counts plus digest prefixes. No source URL,
names, passwords, raw matches, diagnostics or node payloads are retained or
shown. Existing Profiles/Nodes identity labels are defensively redacted in
rendering if they resemble credential-bearing URLs or keys; the original IDs
remain intact only for daemon-side lookups and CAS.

The user must explicitly press "y" after reviewing the node diff and the
warning that removal/rebinding can make later Core Apply fail. A staged write
binds the exact snapshot, source revision, base declaration revision,
candidate declaration SHA and runtime overlay SHA. The daemon re-materializes
and CAS-checks these independently. A successful-looking Stage response is
not enough: an independent status readback must show only the expected
declaration revision increment with unchanged config revision, applied
generation and Last Known Good identity. The Core is neither checked nor
applied by this operation; Dashboard [1] "a" remains a separate guarded
compile/confirm/Core-check/Apply flow.

Cancelled, stale, malformed, too-small-terminal, partial-source-list,
recovery, uncertain-transport or forged-digest conditions refuse a write or
success assertion. An in-flight write may commit after the UI exits; it is
never automatically retried. No TUN and no subscription/ISP routing layers.

## Remaining work

Real end-to-end TUI user acceptance and two-architecture cold-install remain
outstanding, along with 28-group production CN resources and Group/Proxy DNS,
real recovery/#59, 72h traffic stability and signed offline distribution.
Never infer MVP Beta readiness from this narrowly scoped UI improvement.
