# ADR 0179: Proxy DNS native route-pair and source-map integrity

Status: implementation / CI pending (M5 correctness hardening, T10 and T26 partial)

## Problem

A compiler-side existence check for a Proxy DNS resolver is insufficient to prove the
final native configuration uses it for the intended applications. A synthetic or
unrelated `resolve` can make a resolver appear bound while Selected, Global or a
proxy-bound user group routes without the matching pre-resolution step.

The verified ADR 0177 Proxy DNS TCP detour proves only its scoped real-Core
synthetic traffic. The approved Core's Group DNS / Selected route to a private
resolved address remains unresolved under ADR 0178.

## Decision

At the final native configuration boundary, reject the complete candidate unless:

- exactly one Selected synthetic outbound route targets CurrentSelected, with an
  immediately preceding Proxy DNS `resolve` using identical match predicates;
- each of Global and GlobalNoPrivate has the same adjacent, exact-predicate
  `resolve → route` pair;
- every source-mapped, proxy-targeted user route without Group DNS has its
  own adjacent Proxy DNS `resolve` with matching group, layer, FINAL flag,
  target, an outbound equal to TargetCatalog resolution, and exact native rule contents;
- a Proxy DNS `resolve` in the user source map cannot be orphaned,
  forged, duplicated or indexed outside the final native rule array.

Only the action/resolver/outbound fields are allowed to differ across a pair.
No runtime DNS query is implied by a matching JSON pair: the output is
compiler evidence, not a substitute for the existing native traffic tests.

## Evidence and non-goals

The regression test uses full `CompileNativeConfig`, not only the helper,
including adversarial route and source-map drift. No new privileged listener,
TUN, subscription/ISP routing, DNS fallback or core feature is introduced.

Required before merge: exact-head ordinary CI, all four Go Race shards and
managed-core integration. If relevant native provenance workflow runs, it must
also pass. Keep all existing T22/T24/T20/T25 release flags unchanged; no
release claim or stable `main` change is justified by these tests.
