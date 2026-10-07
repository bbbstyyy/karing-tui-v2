# ADR 0051: Validate declared DNS roles with fixed-core network observation

- Status: Accepted
- Date: 2026-10-07

## Context

The project DNS model separates bootstrap, outbound/node, direct-target, proxy-
target, group and global fallback roles. Compiler tests prove dependency closure
and generated tags, but cannot prove that the pinned core actually uses those
transports and detours for live connections.

## Decision

The managed-core integration suite now runs local DNS servers, a pass-through
HTTP proxy and a TCP target and records query names and CONNECT destinations
while using the approved KaringX/sing-box binary.

Observed paths are:

1. Global fallback DNS queries the declared fallback server and reaches the
   resolved target.
2. Bootstrap resolves a domain-valued outbound DNS server; that outbound
   resolver then resolves a domain-valued proxy-node server.
3. Proxy DNS resolves a Selected destination through the CurrentSelected HTTP
   proxy detour before the target proxy connection succeeds.
4. Group DNS resolves a group-bound destination through its declared
   CurrentSelected detour, after which the group's DIRECT action reaches the
   target without silently using Direct DNS or proxying the target.
5. Direct DNS resolves an otherwise FINAL/DIRECT domain request and reaches the
   target without using the proxy.

The daemon advertises `dns_runtime_paths_observed=true` because these paths
are now exercised on the pinned core. Lowerer capabilities remain separate from
runtime observation.

## Safety and scope

The integration DNS servers answer controlled names with loopback A records and
return no AAAA answer. No public resolver or external network is required.

This does not claim support for every Karing DNS feature. FakeIP, system DNS
takeover, ECS, static hosts, additional transports, address-family policy and
an explicit user-facing remote-proxy hostname-resolution mode remain separate
work.

The current proxy/group DNS model deliberately pre-resolves destinations using
declared resolvers. A future remote-resolution option must be modelled and
tested separately rather than inferred from HTTP/SOCKS behavior.

## Validation

`TestManagedCoreRealDNSPaths` verifies exact query names and proxy CONNECT
ports for bootstrap/outbound, proxy, group and direct DNS. The existing
route-outcome test verifies global fallback DNS.

Compiler/domain tests continue to reject missing bootstrap dependencies,
dependency cycles, unavailable detour targets and unsafe pre-resolution cases.
