# ADR 0233: read-only CN source readiness and full 28-group Linux evidence

Status: MVP-2 / MV-03 + MV-07 partial implementation candidate.
**Not** CN-enabled MVP, not permission to redistribute rules.

## Scope

Expose `GET /v1/cn/resources/readiness` on the existing protected Unix
socket Daemon API as an immutable pinned source inventory. It reports:
- Karing repository/commit/source path, exactly 28 groups/6 default enabled;
- group ID/source order/default enablement/target and source field counts,
  including fields retained as Linux `process_name` and Android-only
  `package` values that cannot be lowered on Linux;
- 68 logical resource references (including CN region auto-append),
  67 candidates in the pinned asset inventory, and the one explicitly
  upstream-absent `geoip:bing` reference;
- `distribution_ready=false` and the unresolved upstream-data-license
  blocker, separately from the dangling asset blocker.

This response carries `evidence=pinned_source_inventory_only`: it does
**not** examine installed local files, claim that any user declaration can
currently apply CN, mark licensed data redistributable, or simulate/observe
a Core request. The endpoint has no write operations and no user input,
does not edit the current generation or LKG, and exposes only immutable
built-in Karing source metadata. POST/other mutation methods are refused.

## Semantic proof and missing asset protection

A comprehensive deterministic Linux test enables *each* of the 28 source
groups in the pinned snapshot and compares its complete lower-to-IR
predicate sequence against the independent source columns:
`rule_set_build_in`, `domain_suffix`, `domain_keyword`, `ip_cidr`
and Linux `processName`. No Android package atom appears on Linux,
matching the observed Karing branch. Every group retains its source
order, typed target, `match_any` (OR) and L1 custom layer. The compiler
must preserve the same 28 source-map entries and a FINAL entry; no
rewriting to a two-rule/direct-only approximation is allowed.

When Bing is explicitly enabled, the otherwise successful Core routing
compile must retain `geoip:bing` in its rule-set closure. A catalog
missing that reference must fail with `ErrUnresolvedRuleSet` before
artifact generation; there is no implicit DIRECT bypass. Tests use
synthetic paths and hashes solely to prove binding semantics, not to
claim that the missing licensed asset is installed or distributable.

## Limits before MV-03 / MV-04 / MV-07 sign-off

A full CN-enabled product still needs legal provenance for every generated
rule file, an evidenced compatibility policy for the dangling Bing ref,
immutable signed/hashed offline assets, and Core integration exercising
all 28 groups, five-layer priority/FIRST/FINAL/blocking, regional appends
and group/Direct/Proxy/Outbound/bootstrap DNS. A live Core route can
only be marked verified after observing actual destination/outbound and
DNS requests. MV-03, MV-04 and MV-07 remain open. No subscription/ISP
routing or TUN is added, and stable main remains unchanged.

Merge gate: final-head fmt/Vet/build/unit/integration compile, Race 4/4,
pinned managed Core integration, linux-amd64/arm64 native provenance and
CN resource audit. Tests do not authorize an MVP release.
