# ADR 0240: one real Core for CN L1, safe Group DNS and independent CN region append

Status: MVP-2/MVP-3 partial; **not** MV-03/MV-04/MV-07 or Beta acceptance.

## Decision and test

A new \`integration && linux\` test runs a single pinned native Core with:
- the complete original 28 CN groups, source commit, source order, targets
  and explicit on/off overrides (all 28 enabled here to cover closure);
- one independently declared domain-only Custom L1 group interleaved before
  CN groups and bound to a real Group-role TCP DNS server via CurrentSelected;
- GeoSite and GeoIP "cn" auto append in their own layers, after L1;
- a real Direct UDP DNS server, selected HTTP CONNECT proxy and local echo;
- an explicit FINAL BLOCK to distinguish an actual region match from fallback.

The test asserts observed DNS questions, proxy CONNECT destinations, target
echo, negative destinations and immutable source-map/provenance. A missing
region resource and unsafe Group DNS bound to a CN group with IP predicates
must fail closed without altering the applied/Last Known Good generation.
All rule-set contents are ephemeral synthetic files with private hashes:
**they are not upstream CN assets**. No external DNS/Internet or TUN needed.

## Intentional limitation

The current compiler cannot safely pre-resolve Group/Proxy DNS for a group
whose original matcher needs destination IP or opaque rule-set evaluation.
The CN 28 groups mostly use those matchers. This test therefore proves safe
coexistence and **explicit rejection**, not full original CN group-DNS support.
The missing semantic implementation remains a blocker for MV-04; do not
silently narrow matchers to pretend it is supported.

The independent DNS-path tests cover Proxy, Node/outbound, Bootstrap and
other role behavior, but cannot themselves prove the entire CN semantic
matrix. Source resource license closure, upstream \`geoip:bing\` absence,
restore/#59, dual-arch offline installation and 72h operation remain
release blocking.

Require final-head Go fmt/Vet/tests/build, four Race shards, native pinned
Managed Core traffic on the integration runner and amd64/arm64 Provenance.
