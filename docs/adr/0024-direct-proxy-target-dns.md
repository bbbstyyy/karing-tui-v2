# ADR 0024: Bind Direct and Proxy target DNS without widening fallback behavior

- Status: Accepted
- Date: 2026-10-05

## Context

Outbound DNS now resolves proxy server hostnames, but target-domain DNS still had two separate unresolved roles:

- Direct DNS for destinations sent through DIRECT;
- Proxy DNS for destinations whose selected route is a proxy target.

Karing distinguishes these roles. Its Proxy DNS "proxy" mode sends DNS-server traffic through the current selected proxy, while Direct DNS is dialed directly. The approved sing-box 1.13.19 core exposes two mechanisms needed to preserve this without TUN:

- outbound dial option `domain_resolver`;
- non-final route action `resolve`, which fills destination addresses and then continues rule matching.

Core source confirms that `resolve` preserves the original destination FQDN and that the connection manager consumes the resulting destination-address list when dialing the final outbound.

## Decision

`CompileRuntimeDNS` closes the following roles in deterministic order:

1. Outbound plus its Bootstrap chain;
2. optional Direct plus Bootstrap dependencies;
3. optional Proxy plus Bootstrap dependencies.

Bootstrap dependencies are emitted once on first use.

Outbound, Bootstrap, and Direct DNS transports use the core's native direct dial path and therefore omit `detour`.

Proxy DNS transport uses `CurrentSelected` as its detour, matching Karing's proxy-mode semantics. This does not make Proxy DNS the root DNS fallback.

Fallback remains unsupported and an explicitly configured Fallback binding fails compilation.

## Direct target DNS

When Direct DNS exists, the native DIRECT outbound receives:

`domain_resolver: <direct-dns-tag>`

This makes direct-domain dialing explicit and keeps it independent from node-server Outbound DNS.

## Proxy target DNS

`BindProxyTargetDNSRouting` adds a non-final resolve action before proxy-target final routes.

The fixed Selected inbound becomes:

1. `in-selected -> resolve(server=ProxyDNS)`
2. `in-selected -> route(out-current)`

For user five-layer rules and FINAL whose target is CurrentSelected, Global URLTest, Custom URLTest, or Specific Node, the compiler emits the same resolve/route pair and records both low-level rules in the source map.

DIRECT and BLOCK targets are not given Proxy DNS resolution.

## Ambiguous matcher policy

A proxy-target rule that contains destination `ip_cidr` or any opaque `rule_set` is rejected by this binder.

Those predicates may require destination resolution before the compiler can know whether the rule is the selected route. Resolving first with that rule's Proxy DNS would create a circular dependency and could leak queries or alter GeoIP decisions.

This conservative gate can later be relaxed only when rule-set metadata and a separate classification resolver make the pre-resolution dependency explicit.

## Native closure validation

The native emitter verifies:

- Direct resolver tags exist before attaching them to DIRECT;
- only the compiled Proxy DNS server may carry an outbound detour;
- that detour is exactly CurrentSelected;
- every DNS detour references a materialized outbound;
- every route resolve server exists in the DNS closure;
- configuring Proxy DNS without binding at least one route resolve is invalid.

The root DNS final remains the predefined REFUSED server. Direct/Proxy support therefore does not silently become a global resolver.

## Still pending

- Group DNS semantics;
- Fallback DNS semantics;
- classification/GeoIP resolution for IP-dependent proxy rules;
- encrypted DNS transports;
- cache policy and controlled DNS behavior fixtures.
