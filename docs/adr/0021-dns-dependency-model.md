# ADR 0021: Model DNS roles and bootstrap dependencies before native emission

- Status: Accepted
- Date: 2026-10-05

## Context

The project cannot treat DNS as one global resolver. The plan requires distinct startup/node resolution, direct-target resolution, proxy-target resolution, per-group overrides, and fallback behavior.

The first native emitter therefore rejects domain-valued proxy node servers instead of silently using a system/default resolver. Before lifting that restriction, the declaration model needs a dependency graph that can detect missing bootstrap paths and cycles.

## Decision

`internal/domain.DNSPlan` introduces explicit DNS roles:

- Bootstrap
- Outbound / Node
- Direct
- Proxy
- Group
- Fallback

A `DNSProfile` has a stable ID, role, explicit transport, server, port, and optional Bootstrap profile dependency.

The first transport slice is deliberately limited to UDP and TCP. TLS/HTTPS/QUIC and richer dial/detour options require additional typed fields and approved-core fixtures rather than being passed through as arbitrary source JSON.

## Bootstrap rules

Every remote DNS server uses an explicit non-zero port.

If the DNS server is an IP literal, it must not declare a Bootstrap dependency.

If the DNS server is a domain name, it must reference a Bootstrap-role profile.

Bootstrap profiles may themselves name another Bootstrap profile, but the complete dependency graph must be acyclic and eventually terminate at IP-literal endpoints.

Missing references, role mismatches, self-reference, and cycles fail validation.

The cycle walk follows declaration order, so diagnostics are deterministic rather than depending on map iteration.

## Role slots

The plan may designate stable profile IDs for:

- Outbound DNS
- Direct DNS
- Proxy DNS
- Fallback DNS

Each designated ID must exist and carry the corresponding role.

Group profiles are not placed in one global slot because multiple route groups may have independent DNS bindings.

## Route-group DNS bindings

`ValidateActiveRouteBindings` checks only enabled routing groups.

An enabled group with `DNSProfileID` must reference an existing Group-role profile. A disabled group may retain a stale or future DNS binding without blocking the currently active runtime closure.

BLOCK targets continue to reject DNS bindings at the routing-domain layer.

## Why this is not native DNS support yet

This ADR deliberately stops before emitting sing-box `dns.servers` or `dns.rules`.

The next compiler stages still need to establish:

- how each role maps to explicit dial detours;
- how Outbound DNS is attached through `domain_resolver` to domain-valued node servers;
- Direct versus Proxy target-resolution behavior;
- per-group DNS route actions without overriding node bootstrap resolution;
- explicit fallback behavior;
- TLS/HTTPS server-name/bootstrap semantics;
- cache partitioning and invalidation.

Until those are implemented and exercised with controlled DNS fixtures, the native emitter continues to reject domain-valued node servers and group DNS bindings.
