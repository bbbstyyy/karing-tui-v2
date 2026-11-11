# ADR 0246: real managed-Core source refresh, stable-node rebind and explicit re-apply

Status: **MVP-1C / MV-02 partial**, not MV-02 or MVP Beta acceptance.

## Decision and real traffic proof

Extend the Linux `integration` case `TestManagedCoreRealMVPImportedHTTPFlow`
on the pinned approved Core, an ordinary user, and loopback-only local
services. After a protected first-run source import and confirmed Core apply,
a second valid subscription snapshot changes one HTTP proxy's endpoint while
retaining its source key and stable NodeID.

The test must observe all of the following:
- The source refresh accepts a new immutable snapshot and retains exactly
  the same stable NodeID. Subscription-provided route/FINAL is still ignored.
- Read-only declaration Preview reports zero added/removed and one retained
  node, a different SHA-256 candidate and the original source/base revisions.
- A deliberately wrong preview digest is rejected. An exact user-equivalent
  Stage succeeds once; an identical Stage replay fails its CAS guard.
- Staging **alone** does not change current config revision, Applied, LKG or
  the still-live old proxy's real SOCKS5 traffic.
- A second checked compiler/Core Apply creates a new verified generation and
  its LKG. Rule and Selected SOCKS5, plus Rule HTTP CONNECT, now reach the
  new upstream with an observed echo; the retired proxy receives no hits.
- A subsequent malformed source update preserves the *new* accepted snapshot,
  running generation/PID, LKG, and traffic. An offline Core stop/restart
  continues serving through the new upstream without refreshing the source.
- Private authentication remains in the sealed native artifact but does not
  leak through public preview/refresh/stage/apply responses. No subscription
  routing, TUN, or unmanaged system proxying is introduced.

This is a stronger real-runtime longitudinal check than testing the
snapshot-to-declaration API only with SQLite fixtures. It exercises real
routing and the explicit protected user API path, not a Bubble Tea terminal
keystroke script or production CN rules/resources.

## Non-acceptance boundary

This **does not** validate the complete TUI workflow, multiple real external
subscriptions, CN 28-group Group/Proxy DNS semantics, authorized offline rule
assets, VM restore/#59, dual-architecture cold-install or 72-hour durability.
Source changing is simulated by an intentionally controlled HTTP server; no
end-user credentials or downloaded resources are committed to test assets.

Only a final exact commit with Go fmt/vet/tests/build, Race 4/4, pinned
Managed Core Integration (test actually executed, not skipped), and both
native amd64 and arm64 Provenance checks may be integrated into the
development branch. `main` remains unchanged.
