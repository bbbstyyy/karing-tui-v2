# ADR 0235: real Core five-layer precedence with all 28 pinned CN groups

Status: MVP-2 / MV-03 **partial** real traffic integration candidate.
Not a licensed CN production resource bundle, not MVP Beta acceptance.

## Problem and decision

The source inventory and typed compiler already preserve Karing's 28 CN
groups, six default-enabled groups and all Linux predicate families.
A valid source-map is not by itself evidence that the pinned Core follows
the intended routing priority, or that absent CN resources fail closed.
The existing five-layer Core experiment uses synthetic custom rules; the
existing CN experiment enables only selected CN groups.

Add `TestManagedCoreRealCNAll28GroupsFiveLayerPrecedence` on an ordinary
Linux UID to combine the two evidence paths. The test uses the immutable
pinned CN source snapshot, explicitly enables **all 28 groups** (including
default-disabled `cn.bing`), preserves original source order/targets,
and binds every referenced rule-set name in the 68-ref inventory.

## Local, synthetic resource behavior

The test places only TWO newly generated rule-set contents into the
private hashed Core artifact store: a single-rule loopback match and an
unmatched documentation-only benchmark prefix. Every logical resource ref
points to one of those synthetic contents. The `geoip:bing` ref is
**explicitly synthetic for this test**, because Karing's pinned upstream
asset inventory lacks that file. This does not provide an equivalent Bing
rule, an authorized redistribution license, a sanctioned product fallback,
or a way to enable CN in a user configuration.

The native Core must check and apply that declaration with full pinned
28-group L1 source-map order and authentic native rule-set manifest,
followed by L2 GeoSite, L3 GeoIP, L4 ACL, and FINAL. Three independent
local HTTP proxy witnesses and one echo destination distinguish which
outbound actually receives the connection.

The stages use explicit new checked Core generations. An all-28 enabled
CN Custom L1 `geoip:bing` synthetic hit must choose CurrentSelected
even when L2/L3/L4 would match. When Custom is disabled, L2 must take
priority; when L2 is disabled L3 must win; with both disabled L4 must
BLOCK without direct or proxy traffic; and only after L4 is disabled
may FINAL DIRECT reach the echo target.

An intermediate staged declaration intentionally omits the synthetic
`geoip:bing` resource while CN remains enabled. Compilation must
reject with `declaration.ErrRuleSetResourceMissing` at the earliest
metadata preflight (the lower-level `compiler.ErrUnresolvedRuleSet` is
covered by separate catalog-binding tests); no partial generation may become
Applied/LKG. The previous valid Core must still carry the observed
proxy traffic after the failed apply, with no silent DIRECT route.

## Limits / release gate

This test proves five-layer **behavior with original CN group metadata
and synthetic rule content** on pinned native Core. It does not validate
licensed production CN rule contents, all 68 individual real match cases,
CN-specific real DNS/group overrides, region auto-append, or dual
architecture end-user offline boot. MV-03, MV-04 and MV-07 stay open,
along with real restore, 72h burn-in and unprivileged delivery.

No TUN, subscription/ISP routing, or modification of stable `main`.
The PR stays Draft until the exact final SHA passes Go fmt/Vet/test/build,
integration compile, all Race 4 shards, real Managed Core integration,
amd64/arm64 provenance and CN resource audit. Any rebase requires fresh
final-head evidence.
