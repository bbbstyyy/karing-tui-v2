# ADR 0023: Insert Outbound DNS with an explicit REFUSED default

- Status: Accepted
- Date: 2026-10-05

## Context

The Outbound/Bootstrap DNS lowerer can already produce an acyclic typed resolver closure and bind the Outbound resolver to domain-valued proxy server addresses.

The native emitter previously rejected every domain-valued node and omitted the root `dns` object. Simply inserting the resolver servers without an explicit `dns.final` is unsafe because sing-box uses the first DNS server when `final` is empty. Setting `final` to the Outbound resolver would also be unsafe: Outbound DNS is currently defined only for resolving proxy-server addresses, not for Direct, Proxy, Group, or fallback target resolution.

The approved KaringX/sing-box 1.13.19 baseline includes a Karing-specific typed DNS transport named `predefined`. Its `rcode` field accepts DNS RCODE names such as `REFUSED`.

## Decision

When a compiled Outbound/Bootstrap DNS closure is present, `CompileNativeConfig` emits a root DNS object containing:

1. the dependency-first UDP/TCP resolver closure;
2. a fixed internal server tagged `dns-fail-closed` with:
   - `type: "predefined"`
   - `rcode: "REFUSED"`;
3. `final: "dns-fail-closed"`.

The Outbound resolver is **not** the root DNS final.

This means that only components carrying an explicit `domain_resolver` reference can use the Outbound resolver. Any DNS path whose role has not yet been modeled receives an explicit REFUSED response rather than silently inheriting the first server.

## Node-server resolution

A domain-valued proxy node is accepted by the native emitter only when:

- it carries a non-empty `domain_resolver`;
- that value is exactly the compiled `OutboundResolverTag`;
- the resolver tag exists in the emitted DNS closure.

An IP-literal proxy node must not carry a resolver.

This repeats the invariant already enforced by `BindNodeDomainResolver` at the final assembly boundary.

## Resolver dependency checks

Native DNS assembly requires:

- unique generated DNS tags;
- non-zero explicit ports;
- only the currently approved UDP/TCP server types;
- DIRECT detour for every Outbound/Bootstrap DNS transport;
- IP-literal DNS endpoints to carry no bootstrap resolver;
- domain-valued DNS endpoints to reference a resolver that was emitted earlier in dependency order;
- the declared Outbound resolver tag to exist in the closure.

The fixed `dns-fail-closed` tag must not collide with any generated resolver tag.

## Manifest

The native manifest records the emitted DNS server tags, including the fail-closed final tag, in deterministic order. This makes the generated resolver closure inspectable together with the config SHA-256, inbound/outbound tags, and rule-set resources.

## Real-core compatibility gate

The managed-core integration fixture uses a domain-valued HTTP proxy node, binds it to an explicit IP-literal Outbound DNS server, emits the fail-closed root DNS envelope, and sends the resulting config through the exact approved core's existing `check/run` path.

The test does not require external DNS reachability: readiness remains local and does not dial the selected proxy node.

## Remaining boundaries

This ADR does not define target DNS. Still pending:

- Direct target DNS;
- Proxy target DNS;
- per-route Group DNS actions;
- Fallback semantics;
- encrypted DNS transports;
- cache partitioning/invalidation;
- controlled DNS traffic fixtures.

Until those are implemented, `routing_ir`, `proxy_inbounds`, and `managed_apply` remain false.
