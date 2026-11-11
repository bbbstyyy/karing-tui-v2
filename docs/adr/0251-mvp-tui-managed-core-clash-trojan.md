# ADR 0251: pinned-Core Clash/Trojan replacement through Unix TUI

Status: MVP-1C / MVP-3 / MV-02 and MV-05 **partial**, not MVP Beta.

## Scope of the real check

The existing pinned Core integration `TestManagedCoreRealMVPImportedClashYAMLTrojanFlow`
already imports a real Clash YAML source with a locally hosted authenticated
Trojan/TLS peer, creates a first-run proxy-only declaration, performs protected
Core Check/Apply and tests SOCKS5 and HTTP CONNECT echo traffic. It then accepts
a harmless rename and later a new valid source that removes the selected node;
ordinary source Preview/Stage refuse silent replacement while the old Core and
LKG continue to serve authenticated traffic.

This increment keeps those preconditions but replaces the final direct API
migration calls with a **real Bubble Tea TUI using the same daemon over Unix
socket**, while the pinned Core actually runs:

1. Nodes [3] → `m` reviews the newly accepted node's exact stable identity,
   diff and non-apply state. No Core change or declaration commit may occur.
2. `y` performs a single protected CAS declaration Stage through the Unix
   client. The durable declaration must advance once and bind CurrentSelected
   default and member to the new node. Applied/LKG still point to the old
   real Core generation and the old Trojan continues to serve real SOCKS5.
3. Dashboard [1] → `a` displays a separate compiler-only preview and explicit
   Core restart risk, without changing the old generation.
4. A **second independent `y`** sends checked Apply. The TUI must read back
   durable Core generation before claiming success. The new generation and
   LKG must match and advance exactly one config revision.
5. SOCKS5 Rule/Selected, HTTP CONNECT and a loopback echo prove traffic now
   goes through the *new* Trojan/TLS peer; the retired peer receives none.
   The native artifact must retain password and strict certificate validation.
6. A later unsupported subscription refresh and an offline Core restart still
   preserve this verified new generation, not an implicit DIRECT fallback.

This proof uses the actual daemon/Core/TUI client protocol and SQLite but
drives the Bubble Tea model with scripted keystrokes rather than a physical
terminal. It is only the strict first-run, one-profile proxy-only supported
subset. It does **not** authorize migrating an independently persisted live
CurrentSelected intent, a CN 28-group configuration, or subscription-supplied
routing/ISP rules.

## Pinned native schema compatibility

The managed-core TUI test exposed an actual Apply UX blocker: the pinned
compiler Schema ID contains the trusted separator `@` followed by its build
digest. The generic `inspectionSafeID` redactor is intentionally hostile to
untrusted URLs and therefore rejects `@`, but that redactor is not a valid
validator for native compiler receipts. The protected TUI Apply preview now
requires exact equality with the build's `compiler.NativeSchemaID`, instead
of weakening the untrusted-source sanitizer. Unit tests accept that exact
pinned schema and reject other printable, malformed and URL-shaped values.

## Explicit remaining blockers

The final exact PR SHA must pass full Go CI and Race 4/4, pinned Managed Core,
and both native Linux amd64/arm64 provenance paths before merge. The public
MVP Beta gate still blocks on CN rules and Group/Proxy DNS production semantics,
licensed offline rule closure including `geoip:bing`, real recovery and Issue
#59, 72-hour mixed traffic, and actual dual-arch user installations. Do not
modify `main`, enable TUN, or claim Beta from an isolated TLS fixture.
