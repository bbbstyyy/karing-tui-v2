# ADR 0250: Real Unix-socket TUI to daemon selected-node Stage evidence

Status: **MV-05 / MVP-3 partial**, not a production Core or release claim.

## Exact user path and negative race

`TestMVPRealUnixTUIExplicitSelectedRebindStagesOnly` creates a real SQLite
source, accepted replacement snapshot and existing proxy-only declaration
that still refers to a removed selected node. It runs the *actual daemon
HTTP handler* on a private Unix socket and drives the public Bubble Tea
TUI model through the real `client.New(socket)` transport, without fake
profile/preview/stage responses.

1. Profiles `b` preview is refused when the old selected ID has gone;
   a conditional hint points the operator to Nodes [3], `m`.
2. Nodes [3], `m` selects the exact enabled node in the current snapshot.
   The preview reports its stable ID, source/declaration CAS and counts;
   it is read-only until the operator confirms with `y`.
3. The Stage is a single optimistic API + SQLite transaction, then the
   TUI reads back persistent declaration status. Applied/LKG, runtime,
   configuration revision and the accepted source remain unchanged.
4. A repeated `y` cannot replay the same Stage without another preview.

`TestMVPRealUnixTUISelectionIntentRaceFailsClosed` persists an independent
CurrentSelected intent **after** a valid preview, before `y`. The daemon
refuses the stale Stage, leaving both the old declaration and independent
selection intent intact. The TUI reports uncertainty/refusal without
claiming staged success or automatically retrying.

The handler is in-process and Core is deliberately absent in these tests,
but the Unix socket transport, HTTP framing, TUI state transitions,
source/overlay/declaration guards and SQLite are real. The existing
pinned-Core Trojan/TLS check in #132 covers an authenticated selected-peer
switch through a separate checked Apply. This is **not** a physical terminal
keystroke recording or a full user acceptance.

## Scope and release boundary

No new permission exists to migrate a previously persisted CurrentSelected
intention. Such a migration would require its own rollback-safe two-phase
transaction bound to the applied generation; never rewrite live selection
as a side effect of subscription refresh. This increment cannot close
production CN Group/Proxy DNS, licensed resource closure including
`geoip:bing`, Issue #59 actual restore, 72h mixed traffic or dual-arch
offline packaging. Linux only; no TUN or subscription/ISP route layer.
Require exact final-head Go format, Vet, tests/build, Race 4/4,
Managed Core and native amd64/arm64 Provenance before integration.
