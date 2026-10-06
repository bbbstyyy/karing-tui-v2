# ADR 0040: Lower region auto-append after explicit GeoSite and GeoIP entries

- Status: Accepted
- Date: 2026-10-06

## Context

ADR 0030 kept `RegionAppendPlan` separate from the 28 CN preset groups but deliberately did not define runtime insertion order.

Two independent sources now agree on the visible ordering contract:

1. the pinned 2026 Karing diversion UI builds each GeoSite and GeoIP section by adding all explicit user-selected entries first, then appending the active region entry when the corresponding `autoAppendRegion*` switch is enabled;
2. the last publicly inspectable Karing sing-box builder inserts the region GeoSite rule at the GeoSite-to-GeoIP/ACL boundary and the region GeoIP rule at the GeoIP-to-ACL/end boundary.

The historical builder contains asymmetric paths that can call the region helper without re-checking the auto-append switch. Because that implementation predates the pinned application snapshot and conflicts with the pinned UI/settings contract, those paths are treated as historical defects rather than compatibility requirements.

## Decision

`domain.ApplyRegionAppend` augments an already ordered five-layer `RoutingPlan`.

When enabled:

- `geosite:<region>` is appended after every explicit GeoSite group;
- `geoip:<region>` is appended after every explicit GeoIP group;
- both synthetic groups target DIRECT;
- the existing explicit group order is unchanged;
- the synthetic order is the previous last order plus one, or one for an empty layer.

The stable synthetic IDs are:

- `region:auto-geosite:<region>`
- `region:auto-geoip:<region>`

The function is pure with respect to its input routing plan and clones matcher trees before returning the augmented plan.

## Independent switches

`RegionAppendPlan.GeoSiteEnabled` and `RegionAppendPlan.GeoIPEnabled` independently control whether the synthetic entry exists.

The wider `RoutingLayerSwitches` remain authoritative for whether a complete GeoSite or GeoIP source participates in active routing. A region entry may therefore remain represented in an augmented plan while its entire source layer is globally disabled.

## Duplicate behavior

An explicit user entry for the same logical reference is not removed or merged.

For example, an explicit `geosite:cn` rule remains before the synthetic `geosite:cn -> DIRECT` rule. This preserves the user's higher-priority binding while retaining automatic regional fallback behavior.

Resource dependency collection may deduplicate the immutable rule-set artifact itself; route rules are not deduplicated because they can have different targets, DNS bindings, source identities, and diagnostics.

## Validation

The lowerer rejects:

- an invalid region plan;
- an invalid input routing plan;
- order overflow when the final explicit order is `uint32` maximum.

It does not silently renumber existing groups.

## Capability boundary

`region_append_lowerer=true` means deterministic RoutingPlan augmentation is implemented and tested.

This does not yet mean the declaration schema persists the region policy, nor that full `cn_preset` compatibility is complete. Declaration persistence and real-core route-outcome fixtures remain separate work.
