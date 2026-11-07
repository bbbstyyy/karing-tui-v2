# ADR 0180 — Native route provenance closure for T26

Status: draft implementation; native amd64/arm64 and ordinary CI pending.

## Context

The five-layer compiler has a separate native `route.rules` array and a
`source_map` that powers simulated route explanations and generation audits.
ADR 0178/0179 hardened Group/Proxy DNS resolve pairs, but an unrelated BLOCK,
DIRECT, node-bound or FINAL row could still carry missing, reordered or
misleading provenance even when the native config and source-map bytes each
had their own valid digest.

This violates the explanation integrity requirement of `docs/plan.md`
(T26): an explanation may only attribute an actual native rule to the group,
layer, action and target that emitted it. An on-disk hash is not sufficient
evidence that two *different* artifacts describe the same route.

## Decision

Before `CompileNativeConfig` serializes a native config:

- Require a nonempty ordered source-map with exactly one FINAL route and
  exactly the original Custom → GeoSite → GeoIP → ACL → FINAL order.
  Any subscription/ISP layer is rejected.
- Every user-scoped native match rule must have a source-map row; never
  invent or silently drop a group attribution.
- Check entry action, outbound and DNS server against the native rule.
  Independently resolve every route target via `TargetCatalog`; BLOCK
  must be a true `reject` without an outbound or DNS profile.
- FINAL has no group ID or group DNS profile; its native predicate must
  match only the Rule inbound unconditionally. No narrowing, rewriting
  to the Selected inbound or silent fallback is accepted.
- A DNS `resolve` row must identify the compiled Proxy or Group resolver
  and immediately precede a matching route with the same declared target,
  group and layer and identical match predicates.
- Fail before native JSON generation with `ErrNativeConfigClosure` on
  conflicting or absent evidence. Existing release-gate false claims remain
  unchanged.

This is *structural evidence*, not an assertion that sing-box observed a
specific traffic decision. Runtime T26 observed proof and five-layer
CN rule-set closure still require separate controlled traffic fixtures.

## Evidence / limits

Positive no-Core regression covers BLOCK, Direct, SpecificNode,
CurrentSelected and FINAL across all five layers. Negative fixtures mutate
or remove source-map entries and native predicates independently. Existing
Group/Proxy DNS native tests continue to exercise their separate contracts.

No change to actual route ordering, DNS forwarding, TUN, privileged
network configuration, subscription/ISP layers, approved Core pin, or
stable `main`. Exact-head CI (including all four Race shards), Managed
Core and native amd64/arm64 Core Provenance must pass before merge.
