# ADR 0020: Emit a deterministic native config only from a closed dependency graph

- Status: Accepted
- Date: 2026-10-05

## Context

Routing, rule-set, selection, and basic-node compilers now produce validated intermediate outputs, but the managed-core integration test still used hand-written sing-box JSON. That left a gap between the product compiler and the exact approved core's `check/run`.

A whole-config emitter must not become a shortcut around unresolved DNS, mutable resources, or missing target closure.

## Decision

`internal/compiler.CompileNativeConfig` is the first complete native-envelope assembler for the approved KaringX/sing-box 1.13.19 baseline.

Its input is already-validated compiler output plus explicit runtime-only values:

- the three `InboundSet` ports/address;
- authenticated loopback control address and 64-hex-character secret;
- explicit core log level;
- stable target catalog;
- staged/bound routing closure;
- compiled selection closure;
- compiled basic node closure.

It produces:

- deterministic native JSON;
- SHA-256 of those exact bytes;
- a manifest containing schema/core identity, config hash, ordered inbound/outbound tags, and the exact staged rule-set paths/hashes.

## Native envelope

The emitter generates:

1. Rule / Direct / Selected Mixed inbounds using the fixed runtime tags, explicit loopback addresses and `set_system_proxy: false`;
2. one DIRECT outbound;
3. only required basic node outbounds;
4. required URLTest groups followed by CurrentSelected;
5. staged local rule-set declarations;
6. the ordered route rules produced by the routing compiler;
7. `find_process` only when the matcher closure requests it;
8. a loopback Clash API with explicit Bearer secret and `default_mode: "Rule"`.

No TUN, system proxy takeover, route manipulation, external UI download, or privileged listener is emitted.

## Closure checks

Before JSON is emitted, the assembler verifies:

- no duplicate outbound tags;
- every route outbound tag exists;
- every selector/URLTest candidate and default already exists;
- every route `rule_set` tag belongs to the staged rule-set closure;
- every rule-set can render a staged content-addressed local config;
- node compiler metadata and emitted tags agree.

These checks are repeated at the assembly boundary even though lower compiler stages validate their own local invariants.

## DNS boundary

A basic node whose server is a DNS name is rejected with `ErrDNSRequired`.

This is deliberate. The approved core can resolve domain-valued servers, but the product plan requires explicit bootstrap/outbound DNS dependency semantics. Using an implicit resolver just to make early configs runnable would make the later DNS compiler observably incompatible.

IP-literal node servers are sufficient for the initial native `check/run` fixture.

## Control-plane boundary

The Clash controller must be a non-zero loopback address and must not reuse any proxy inbound port. Its secret must be exactly 32 bytes encoded as 64 hexadecimal characters.

The secret is a compiler input, so determinism is defined over the full explicit input set rather than hiding runtime randomness inside the compiler.

## Integration consequence

The real managed-core integration fixture now builds its candidate config through:

`RoutingPlan -> TargetCatalog -> rule-set binding -> SelectionPlan -> basic Node closure -> CompileNativeConfig`

and then sends those bytes through the existing immutable generation/apply/check/run path.

The managed-core workflow is also triggered by changes under `internal/compiler/**`.

This turns the approved core into an executable compatibility test for the compiler schema instead of only a test for a separate hand-written fixture.

## Remaining gates

This does not make `routing_ir` or `proxy_inbounds` generally available yet. Remaining work includes:

- explicit resolver/bootstrap/outbound/direct/proxy/group DNS graph;
- domain-valued node server support through that graph;
- group DNS route action derivation;
- additional typed proxy protocols/transports;
- persistent generation manifest/source-map storage;
- daemon compilation from durable declaration revisions;
- CN preset/resource initialization and compatibility fixtures.
