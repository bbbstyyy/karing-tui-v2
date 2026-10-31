# ADR 0181 — Fail-closed T26 route explanation on inconsistent persisted provenance

Status: implementation submitted; exact-head CI and native Core verification pending.

## Context

ADR 0180 validates the cross-artifact relation of `route.rules` and the
`source_map` immediately before native configuration emission. The
`route explain` endpoint subsequently reads these as separate persisted
artifacts. Its original decoder checked each file's SHA-256 and the
source-map action/outbound/server at each native rule index, but this did
not establish that the recorded layer, target, FINAL identity and scoped
matchers still described the native rules.

Individually valid (or coherently recomputed) file checksums are not
evidence of semantic agreement. `T26` must not attribute a simulated
decision to a fabricated group merely because the hashes match.

## Decision

The read-side validator in `internal/compiler/native_route_persisted.go`
reconstructs the *deterministically addressable* target-tag catalog from
the persisted source-map references and reuses the ADR 0180 native
provenance predicate at the `route explain` load boundary.

- Require ordered source-map rows, actual user-scoped native rules,
  a unique unconditional Rule-inbound FINAL, and only the known
  Custom → GeoSite → GeoIP → ACL → FINAL provenance layers.
- Resolve DIRECT, CurrentSelected, GlobalURLTest, CustomURLTest and
  SpecificNode outbound tags from the typed target references.
  BLOCK must remain a native reject with no outbound or DNS profile.
- Require Group DNS resolve tags to derive from the declared DNS profile
  ID and to be advertised by the persisted manifest; infer Proxy DNS
  resolver from the corresponding Selected synthetic native pair and/or
  source-map resolves, then check consistent adjacent resolve/route
  pairs. No phantom resolver may create a simulated trace.
- Any contradiction returns `ErrRouteExplainIntegrity`; no partial
  explanation or `observed` classification is returned.

## Limits

This check does not replay or authenticate the original declaration,
nor does it sign persisted files. An actor who can rewrite all native
rules, source map, declaration metadata and relevant hashes consistently
cannot be distinguished solely by this check. Likewise, metadata
cannot reconstruct full Group DNS detour policy, live cache behavior or
which outbound actually carried a connection. The report is still
`simulated` or `unknown`, never fabricated `observed`.

The current release gates for T10/T20/T22/T23/T24/T25/T26 remain
unchanged. No TUN, subscription/ISP routing layer, remote DNS,
privileged port, new Core distribution, or change to stable `main`.

## Verification

Add negative daemon API regressions with intentionally recomputed
config/manifest/source-map SHA-256 values, plus a positive compiler
Group+Proxy DNS fixture. Require same-head ordinary CI, four Race
shards, Managed Core integration and native amd64/arm64 provenance
checks before merge. This is a T26 read-side integrity slice, not
complete runtime route observation.
