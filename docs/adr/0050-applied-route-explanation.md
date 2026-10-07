# ADR 0050: Explain applied-generation routes with explicit evidence levels

- Status: Accepted
- Date: 2026-10-07

## Context

The project plan requires route diagnostics to distinguish facts observed from
the running core from offline simulation. An explanation must identify the
configuration generation and, when available, the source layer/group without
inventing data that the core did not expose.

The daemon already persists three immutable artifacts per applied generation:

- native sing-box configuration;
- generation manifest with declaration provenance;
- route source-map linking native rule indexes back to project routing sources.

Recompiling the newest declaration for diagnostics would be unsafe because the
declaration store may be ahead of the applied generation. It could explain a
configuration that is not serving traffic.

The pinned KaringX/sing-box Clash `/connections` endpoint exposes useful
observed metadata such as inbound type, destination, rule text and outbound
chain, but it does not expose the project's stable source-map identity. A
source group cannot therefore be labelled observed merely by parsing the
human-readable rule string.

## Decision

The daemon exposes `POST /v1/route/explain`.

The first implementation is an applied-generation simulator. It loads the exact
applied generation, verifies the config, manifest and source-map hashes, verifies
manifest/config identity and declaration provenance, and evaluates the persisted
native route rules in order.

Responses use explicit evidence values:

- `simulated`: all conditions required for the decisive native rule were
  evaluable from the supplied input;
- `unknown`: an earlier potentially matching rule depends on information the
  simulator cannot prove, so no later rule is claimed as decisive;
- `observed`: reserved for future connection evidence and not advertised yet.

The capabilities are therefore:

- `route_explain_simulated=true`;
- `route_explain_observed=false`.

The request defaults to the Rule inbound and can include domain, IP, port,
network and process name. Direct and Selected entries are evaluated through the
native synthetic inbound rules rather than reconstructed from high-level
declaration assumptions.

The evaluator understands the native conditions currently emitted by the
project: inbound, exact/suffix/keyword/regex domain predicates, IP CIDR,
port/range, network, process name, logical AND/OR and inversion. Local rule-set
membership is currently treated as opaque. Encountering such a potentially
matching rule returns `unknown` and stops evaluation; the simulator does not
skip it to claim a later FINAL route.

Each trace entry records its native rule index and, where present, the persisted
source-map layer, group, target, DNS profile and action. Synthetic inbound rules
are explicitly labelled `synthetic`.

## Integrity boundary

Route explanation is refused if the applied generation has incomplete or
tampered metadata. The source-map rule index must be in range and its action,
outbound and DNS server must agree with the corresponding native rule.

The response always includes configuration revision, generation ID and bound
declaration revision so diagnostics cannot silently drift across generations.

## Observed connections

The pinned core's `/connections` endpoint is sufficient to expose real
connection metadata and outbound chains, but not a stable source-map ID.
Observed connection support must keep these evidence classes separate:

- core connection metadata may be marked observed;
- source-group attribution must remain simulated or unknown unless a stable
  mapping is demonstrated.

The project must not convert a string-form core rule into an apparently
authoritative source-group identity.

## Validation

Unit and API tests cover:

- source-mapped rule and FINAL decisions;
- native Direct synthetic routing;
- opaque rule-set state returning `unknown`;
- invalid input;
- tampered generation metadata refusal;
- HTTP API responses bound to an actually committed applied generation;
- strict rejection of unknown request fields.

Race, build and integration-compile CI cover the implementation. Existing
fixed-core route-outcome tests remain the behavioral reference for real traffic;
the simulator is not counted as observed traffic evidence.

## Consequences

This closes the simulation half of T26 and creates an API that the future CLI
and TUI can consume without parsing generated sing-box JSON themselves.

T26 is not fully closed until observed connection presentation is implemented
with equally explicit provenance. Until then the daemon advertises observed
route explanation as unavailable.
