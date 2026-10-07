# ADR 0052: Keep observed core connections separate from simulated source attribution

- Status: Accepted
- Date: 2026-10-07

## Context

T26 requires diagnostics to distinguish observed, simulated, and unknown
evidence without inventing a complete route chain.

The pinned KaringX/sing-box Clash API exposes authenticated connection snapshots
with destination metadata, inbound identity, traffic counters, rule text and
the selected outbound chain. It does not expose the project's stable source-map
rule index or route-group ID.

The project also has an applied-generation route simulator documented in ADR
0050. That simulator can map native rules back to project source groups, but its
result is still simulation rather than a fact reported by the core.

## Decision

The daemon exposes `GET /v1/connections` when the managed runtime supports the
pinned core connection endpoint.

Each response is bound to a persistent configuration revision and applied
generation ID. The coordinator reads persistent state before and after the core
snapshot and refuses the result if the applied generation changes or a managed
core transition is active.

Connection fields received directly from the pinned core are labelled
`evidence="observed"`. This includes the connection identity, inbound,
destination metadata, traffic counters, human-readable core rule string and
outbound chain.

Source attribution is intentionally separate. When the observed metadata is
sufficient to construct a route-simulation input, the daemon invokes the
applied-generation simulator from ADR 0050 and stores that result under
`source_evidence`. It remains `simulated` or `unknown`; it is never promoted
to observed merely because the surrounding connection is observed.

If the inbound, network, destination or simulator result is insufficient,
source attribution remains `unknown` and the missing condition is reported.

## Capabilities

- `connection_observation` is runtime-dependent and is true only when the
  configured managed core exposes the authenticated connection snapshot path.
- `route_explain_simulated=true` remains the capability for
  `POST /v1/route/explain`.
- `route_explain_observed=false` remains intentional because that endpoint
  does not return a core-observed source-map match.

This capability split prevents a client from treating the simulated source
group as a core-reported fact.

## Safety and consistency

The control endpoint is loopback-only and authenticated through the existing
managed-core control client.

Observation is refused when:

- the core is not running;
- no applied generation exists;
- a managed transition is active;
- the applied revision/generation changes while the snapshot is being read.

The daemon does not parse the core's human-readable rule string to synthesize a
source-map identity.

## Validation

Unit tests verify that:

- observed connection fields stay labelled observed;
- source attribution remains simulated;
- the simulator receives the observed inbound, host/IP, port and network;
- an applied-generation change invalidates the snapshot;
- active core transitions block observation.

The core API client has authenticated loopback response tests and bounded JSON
decoding. Managed-core integration continues to validate the same pinned core
used by the route and DNS outcome fixtures.

## Consequences

T26 now has both evidence surfaces needed by the management plane: explicit
offline/applied-generation simulation and real core connection observation.
The source-group component of an observed connection is still intentionally
labelled simulated or unknown because the pinned core does not expose a stable
source-map ID.

Future CLI/TUI views must display these evidence fields rather than collapse
them into one apparent route fact.
