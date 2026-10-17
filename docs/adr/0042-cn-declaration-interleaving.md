# ADR 0042: Persist CN preset overlays and explicit L1 interleaving in declaration v1

- Status: Accepted
- Date: 2026-10-06

## Context

ADR 0029 preserves the exact 28-group CN preset as an immutable upstream snapshot. ADR 0031 keeps mutable user choices as a typed overlay, and ADR 0039 provides evidence-bounded Linux lowering.

The remaining declaration problem is order.

CN preset groups and ordinary user-created custom groups are both L1 Custom sources. Karing exposes the custom group list as reorderable, so a compatible model cannot permanently force preset groups before or after ordinary custom groups.

At the same time, the declaration must not rewrite the upstream CN JSON or overload the snapshot ordinal as mutable user state.

## Decision

Declaration schema v1 adds:

- optional `routing.cn_preset`;
- optional `routing.custom_order`.

`routing.cn_preset` contains:

- `source_commit`, which must equal the currently supported pinned Karing CN snapshot commit;
- `overrides`, keyed by stable CN group ID and limited to enabled state, typed target, and optional DNS profile.

The declaration model keeps this policy separate from `RoutingPlan.Custom`. The 28 CN groups are materialized only while deriving the effective routing plan.

## Snapshot identity

`source_commit` is mandatory when `cn_preset` is present.

The current accepted value is the exact Karing commit recorded by `preset.CNSourceCommit`. An unknown commit fails closed instead of compiling the same immutable declaration against a silently changed embedded preset after an application upgrade.

Future preset upgrades must migrate declarations explicitly after the old/new/overlay three-way review.

## Interleaving

`routing.custom_order` is a complete ordered list of typed references:

- `kind=custom` references an ordinary declaration-defined Custom group;
- `kind=cn_preset` references one of the 28 stable CN group IDs.

When ordinary Custom groups and CN preset groups coexist, `custom_order` is required.

It must:

- contain every ordinary Custom group exactly once;
- contain every CN preset group exactly once, including currently disabled groups;
- contain no unknown IDs or duplicates;
- preserve the relative order of ordinary Custom groups already expressed by their `order` fields.

The last requirement prevents two declaration fields from contradicting each other. Reordering ordinary Custom groups therefore still updates their normal `order` values; `custom_order` records only the complete merged L1 sequence.

CN groups may be moved freely inside that merged sequence. Their immutable upstream ordinal remains preserved in the snapshot and is not rewritten.

When CN preset is the only L1 Custom source, omitting `custom_order` means the exact snapshot order.

`custom_order` without `cn_preset` is invalid.

## Effective routing

Semantic compilation derives effective routing in this order:

1. parse and validate ordinary routing;
2. load the pinned CN snapshot;
3. apply CN overrides;
4. lower supported CN groups for Linux;
5. interleave ordinary and CN Custom groups;
6. apply region GeoSite/GeoIP auto-append;
7. validate the complete effective routing plan;
8. compute DNS and immutable rule-set closure from that effective plan.

The persisted ordinary `RoutingPlan.Custom` is not rewritten with synthetic CN groups.

## Disabled state and resource closure

All 28 CN groups retain positions even while disabled so enabling a group later cannot give it an undefined priority.

Only enabled groups in an enabled Custom source layer contribute route rules and rule-set resources. Disabling the entire Custom layer therefore removes both ordinary and CN Custom rules from active resource closure without changing their persisted state.

## Capability boundary

`cn_preset_interleaving=true` and `declaration_cn_preset=true` mean declaration persistence and deterministic L1 composition are implemented.

`cn_preset=false` remains intentional until trusted complete offline resource/license closure, unresolved Linux `processName` compatibility, and CN-specific real-core routing fixtures are complete.
