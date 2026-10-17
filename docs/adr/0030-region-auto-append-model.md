# ADR 0030: Keep CN region auto-append independent from the 28 preset groups

- Status: Accepted
- Date: 2026-10-06

## Context

Karing's pinned settings model has two independent defaults:

- `autoAppendRegionGeoSite = true`
- `autoAppendRegionGeoIp = true`

The diversion UI appends the active region code as a DIRECT-looking entry in the GeoSite and GeoIP sections. The project plan explicitly requires these mechanisms to remain separate from the 28 CN custom groups.

The plan also records one unresolved compatibility question: the exact generated-config insertion position and priority relative to user-selected entries must be verified by fixtures rather than inferred only from UI ordering.

## Decision

`domain.RegionAppendPlan` models region auto-append as a separate declaration with:

- explicit lowercase ISO-3166 alpha-2 region code;
- independent GeoSite enable switch;
- independent GeoIP enable switch;
- typed target intent.

`DefaultCNRegionAppendPlan()` returns:

- region `cn`;
- GeoSite enabled;
- GeoIP enabled;
- DIRECT target.

The model exposes deterministic resource references:

- GeoSite enabled -> `geosite:<region>`
- GeoIP enabled -> `geoip:<region>`

For CN defaults this is `geosite:cn`, then `geoip:cn`.

## Fail-closed validation

The current compatibility model permits only a lowercase two-letter region code and DIRECT target intent.

It does not silently reinterpret an invalid region or a proxy/BLOCK target.

## Deliberate compiler boundary

This ADR does **not** define final route insertion order.

The UI evidence shows auto-appended region entries after the displayed user entries in each section, but UI order alone is insufficient evidence for native runtime order. Therefore no route lowerer is added in this stage.

A compatibility fixture must establish:

1. exact GeoSite insertion position;
2. exact GeoIP insertion position;
3. priority relative to explicit user entries with the same region;
4. duplicate handling;
5. source-map identity.

Until then `region_append_model=true` but no region-append compiler capability is advertised.

## Relationship to CN preset

The 28 groups remain L1 custom routing groups. Region auto-append belongs to the lower GeoSite/GeoIP sources and must never be emulated by merely enabling "国内直连".
