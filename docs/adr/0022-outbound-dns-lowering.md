# ADR 0022: Lower only the Outbound DNS bootstrap closure first

- Status: Accepted
- Date: 2026-10-05

## Context

The native emitter currently rejects proxy nodes whose server address is a domain name. The DNS domain model now provides explicit role separation and bootstrap dependencies, but emitting every DNS role at once would mix still-unverified target and group DNS semantics into the startup path.

The approved 1.13.19 core provides new typed UDP/TCP DNS servers and dial-field `domain_resolver` support. A DNS server with a domain-valued endpoint must itself name a resolver.

## Decision

The first DNS lowerer handles only the Outbound / Node DNS role and the Bootstrap profiles reachable from it.

`CompileOutboundDNS`:

1. validates the full `DNSPlan`;
2. requires an explicit Outbound profile;
3. walks only that profile's Bootstrap dependency chain;
4. emits dependencies before dependents;
5. derives stable runtime tags as hashed internal identifiers;
6. emits explicit UDP/TCP server type, server, and port while leaving `detour` empty so the approved core uses its native direct dial path;
7. attaches `domain_resolver` to any DNS server whose own endpoint is a domain name.

Profiles for Direct, Proxy, Group, and Fallback roles may exist in the declaration plan but are not emitted by this stage.

## Why the DNS transport uses the core's direct dial path

Node/bootstrap DNS must be able to start before a selected proxy path is guaranteed usable. The initial lowerer therefore requires direct dialing for the Outbound/Bootstrap resolver chain.

The exact approved 1.13.19 core rejects `detour: out-direct` when `out-direct` is an otherwise empty DIRECT outbound, reporting that detouring to an empty direct outbound makes no sense. At the native JSON boundary, direct dialing is therefore represented by **omitting `detour`**.

The compiler still treats any non-empty detour in this closure as invalid. This is a deliberate narrow bootstrap policy, not an implicit fallback and not a claim that all future DNS roles must be direct.

Proxy-aware target DNS and Group DNS will have separate detour semantics once their dependency graphs are compiled and tested.

## Node binding

`BindNodeDomainResolver` consumes a compiled basic-node closure.

- IP-literal proxy server addresses remain unchanged.
- Domain-valued proxy server addresses receive the compiled Outbound resolver tag through the approved core's `domain_resolver` dial field.
- The original node compiler output is not mutated.
- Missing/unknown resolver tags and conflicting pre-bound resolver values fail closed.

This binding is independent of target website DNS. It resolves only the server address of non-DIRECT proxy outbounds, matching the approved core's dial-field semantics.

## Native-envelope follow-up

ADR 0023 closes the next boundary by inserting this resolver closure into the native envelope with an explicit fail-closed DNS final. The Outbound resolver is therefore available only through explicit `domain_resolver` references and is not promoted to general target DNS.

## Remaining work

- native DNS envelope with explicit non-accidental fallback behavior;
- Direct and Proxy target DNS;
- Group DNS rule/action derivation;
- Fallback role;
- TLS/HTTPS/QUIC transports and server-name/bootstrap rules;
- cache partitioning and invalidation;
- controlled DNS behavior fixtures.
