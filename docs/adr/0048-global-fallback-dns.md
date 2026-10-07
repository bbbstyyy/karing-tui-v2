# ADR 0048: Compile Global fallback DNS into the pinned core default transport

- Status: Accepted
- Date: 2026-10-07

## Context

The project DNS model distinguishes Global fallback from node startup DNS,
Direct DNS, Proxy DNS, Group DNS, and routing FINAL. Before this decision the
declaration schema already carried a fallback profile ID, but the runtime
compiler deliberately rejected that role because its exact core behavior had
not yet been verified.

The pinned KaringX/sing-box baseline exposes a DNS `final` option. At the
inspected core commit, the DNS transport manager uses that tag as its default
transport. Queries that do not match a more specific DNS route therefore use
that transport. This matches the project definition of Global fallback and is
separate from the traffic routing FINAL target.

## Decision

A declaration fallback profile is now part of the runtime DNS dependency
closure. It is compiled like other explicitly configured non-proxy remote DNS
profiles, including bootstrap dependencies for domain-valued DNS server
addresses.

When `fallback_profile_id` is configured, the native compiler writes that
runtime DNS tag to `dns.final`.

When no fallback profile is configured, the compiler keeps the existing
fail-closed predefined `REFUSED` transport as `dns.final`. The project does
not silently inherit system DNS or insert an undeclared public resolver.

Fallback does not replace:

- Outbound DNS used for proxy-node server resolution;
- Direct or Proxy DNS explicit route actions;
- Group DNS resolve/route pairs;
- bootstrap resolution of DNS server hostnames.

## Validation

Unit tests prove closure ordering, bootstrap binding, native `dns.final`
selection, and rejection of missing fallback runtime tags.

The managed-core route-outcome integration test starts a local UDP DNS server,
sends a SOCKS domain request through the Direct inbound, and requires both the
fallback DNS query and the resulting TCP target connection to be observed on
the pinned KaringX/sing-box binary. The same workflow still verifies Rule,
Direct, and Selected route outcomes.

## Consequences

The capability `dns_fallback_lowerer` may be advertised because the behavior
is now compiler-checked and observed on the approved core.

This does not claim full Karing DNS parity. FakeIP, system DNS takeover, ECS,
static hosts, address-family policy, diagnostics, and additional transports
remain separate work items and must not be inferred from this capability.
