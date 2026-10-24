# ADR 0041: Persist region auto-append policy separately in declaration v1

- Status: Accepted
- Date: 2026-10-06

## Context

ADR 0040 established deterministic lowering for the region GeoSite/GeoIP auto-append policy, but the declaration schema still had no way to persist that policy independently from explicit routing groups.

The project plan requires the two region switches to remain independent from:

- the 28 CN preset groups;
- explicit GeoSite/GeoIP groups;
- whole-source GeoSite/GeoIP enable switches.

Materializing synthetic region groups directly into persisted user routing would erase that distinction and make upgrades/diagnostics ambiguous.

## Decision

Declaration schema v1 adds optional `routing.region_append`:

- `region_code`;
- `geosite_enabled`;
- `geoip_enabled`.

When the object is present both enable fields are required explicitly. The runtime target is not user-selectable: region auto-append remains DIRECT by compatibility contract.

When the object is omitted, no region auto-append policy is applied. This preserves existing declaration behavior.

The parsed declaration model keeps `RegionAppendPlan` separate from the persisted `RoutingPlan`. Synthetic route groups are generated only during semantic compilation with `domain.ApplyRegionAppend`.

## Resource closure

Synthetic region rules participate in the same immutable rule-set closure as ordinary rules.

For example, CN with both switches enabled requires declaration metadata for:

- `geosite:cn`;
- `geoip:cn`.

If the corresponding whole routing source is globally disabled, that source contributes no active route and therefore does not require its region resource in the active generation.

Missing active metadata or unavailable content fails closed exactly like any other rule-set dependency.

## Ordering and source map

Compilation preserves the source identities from ADR 0040:

- `region:auto-geosite:<region>`;
- `region:auto-geoip:<region>`.

These entries appear after explicit groups in their respective layers and before later layers. They participate in source maps and diagnostics as synthetic region sources, not as CN preset groups.

## Consequences

The declaration now preserves the independent region-policy dimension without rewriting user route arrays.

This still does not enable full `cn_preset` capability. CN overlay persistence, trusted complete resource packaging, unresolved Linux `processName` compatibility, and route-outcome fixtures remain separate requirements.
