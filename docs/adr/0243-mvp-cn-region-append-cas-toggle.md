# ADR 0243: guarded independent CN region append switches via route-edit CAS

Status: MVP-2 / MVP-3 incremental support, **not** MV-03/MV-05/MV-07 or Beta acceptance.

The ordinary guarded route-edit preview/confirmation/stage contract now supports
ONLY `Enabled` edits of the canonical generated CN region identities:
`geosite/region:auto-geosite:cn` and `geoip/region:auto-geoip:cn`.
A CLI user invokes `config route-preview --layer=geosite|geoip
--group=region:auto-geosite:cn|region:auto-geoip:cn --enabled=true|false
--out=PRIVATE_RECEIPT`, then explicitly `config route-stage --receipt=... --confirm`.
Preview regenerates the exact candidate/native digest; stage rechecks all
declaration/config/selection/generation CAS, recompiles, and commits one
unapplied declaration revision. Core Apply remains a **separate** action.

The patch changes only one of the pre-existing `routing.region_append`
booleans; it refuses absent regions, unrelated country/group IDs, field
combinations, generated target/DNS changes, ID collisions, and no-op edits.
GeoSite/GeoIP remain independent L2/L3 append operations with immutable
DIRECT targets. No subscription/ISP layer or TUN is introduced. Strict
compiler/resource resolution still rejects enabling a missing rule-set,
and the route editor must not auto-create an offline CN resource or bypass
license checks. User credentials, CN 28 source, custom routes, full DNS,
nodes and selection remain semantically identical.

This slice exposes a CLI-only guarded edit, not yet the full TUI toggle and
not live CN rule assets. It must pass final-head Go fmt/Vet/test/build,
Race 4/4, native Managed Core and Linux amd64/arm64 Provenance; a real
Core traffic regression for toggle-on/off is required before claiming
complete MV-03 semantics. Original CN Group/Proxy DNS limitations,
`geoip:bing` and licensing, #59 and 72h durability remain release
blockers.
