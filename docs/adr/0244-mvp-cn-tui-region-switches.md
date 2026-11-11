# ADR 0244: bounded TUI CN region switches with explicit stage-only workflow

Status: MVP-2/MVP-3 partial; not MV-03/MV-05/MV-07 or MVP Beta acceptance.

The applied-declaration inspection projects only three extra non-secret fields:
the literal region code and independent GeoSite/GeoIP append booleans.
The CN region switches are displayed even when disabled, because disabled
generated groups do not exist in the effective routing plan. This is not an
installed resource or live Core indication. No matcher value, credential,
DNS endpoint, original CN source body or Core configuration is exposed.

Page 7 Routing offers two canonical CN switch rows, only when an untruncated,
applied, consistent inspection has no staged declaration. Each enabled switch
must match exactly one generated same-layer DIRECT/no-DNS group; each disabled
switch must have none. Inconsistent/forged identities cannot be edited. The
two canonical identities are `region:auto-geosite:cn` and
`region:auto-geoip:cn`; no country or other region is editable.

The existing `e` key performs one-field compiler preview with revision,
declaration SHA, config revision, selection revision, applied generation and
native digest bindings; only explicit `y` stages the declaration. `t` and
`g` cannot edit an auto-generated region target/DNS. Stage never applies
Core, retries uncertain commits, authorizes CN rule assets or changes the
CN 28 groups. Strict compiler rejection remains authoritative, including
when an off region cannot be turned on due to unavailable rule resources.

This is a guarded operator UI addition, not production CN enablement.
Original CN Group/Proxy DNS limitations, the 68-ref licensing closure
(including absent geoip:bing), Issue #59 real restoration, 72-hour durability
and dual-arch offline packages continue to block MVP Beta.
