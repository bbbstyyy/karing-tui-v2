# ADR 0038: Model routing source switches independently from group enable state

- Status: Accepted
- Date: 2026-10-06

## Context

The routing model already preserves the five source layers and each group's individual enabled state, but the project plan requires separate source-level switches:

- custom routing source;
- GeoSite source;
- GeoIP source;
- ACL source;
- FINAL, which is always present.

A source-level switch is not equivalent to rewriting every contained group's enabled flag. Rewriting group flags would destroy user state and make re-enabling the source unable to restore the previous per-group choices.

## Decision

`RoutingPlan` carries `RoutingLayerSwitches` independently from the ordered group slices.

The domain representation uses disabled booleans so its zero value preserves existing behavior: every non-FINAL source is enabled unless explicitly disabled. FINAL is always enabled.

Declaration schema v1 exposes user-facing optional booleans:

- `custom_enabled`
- `geosite_enabled`
- `geoip_enabled`
- `acl_enabled`

Omitting one of these fields means enabled. Explicit `false` disables that source without mutating any group's own `enabled` value.

## Compiler behavior

A disabled source:

- contributes no active route steps;
- contributes no source-map entries;
- contributes no rule-set resource references;
- does not require group DNS bindings;
- does not change the persisted order, match expression, target, DNS binding, or group enabled flag.

The compiler still validates the stored groups structurally. Disabling a layer is not an escape hatch for persisting malformed target identities, duplicate groups, or invalid ordering.

Synthetic Direct and Selected entry rules and the explicit FINAL rule are unaffected.

## Resource closure

Rule-set closure is computed after source switches are applied. Therefore a declaration may retain exact metadata for a disabled source without loading those resources into the current native generation. Conversely, once the source is re-enabled, every referenced resource must resolve normally and missing content fails closed.

## Consequences

This keeps the two required state dimensions independent:

1. source availability;
2. per-group enable/binding state.

It also preserves backward compatibility for existing declarations because omitted switch fields retain the previous all-sources-enabled behavior.
