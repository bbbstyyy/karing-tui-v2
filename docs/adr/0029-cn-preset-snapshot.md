# ADR 0029: Preserve the CN preset as an immutable upstream snapshot before semantic conversion

- Status: Accepted
- Date: 2026-10-06

## Context

The project must retain Karing's CN preset rather than replacing it with a simplified "China direct / foreign proxy" policy.

The fixed Karing baseline `9d28b22fbbcca5818d147629aae151d49d4dcb7b` contains `assets/datas/preset/cn.json` with 28 ordered custom routing groups and six groups enabled by default. The groups mix built-in rule-set references with domain, IP, Android package, and desktop process fields.

The exact boolean relationship between all of Karing's flat fields is not fully established by the public source snapshot. Converting the file directly into the project's explicit matcher AST before compatibility fixtures exist would risk silently changing routing semantics.

## Decision

The exact upstream CN JSON is embedded verbatim under `internal/preset/cn.json` with source identity:

- repository: `KaringX/karing`
- commit: `9d28b22fbbcca5818d147629aae151d49d4dcb7b`
- path: `assets/datas/preset/cn.json`

`internal/preset.LoadCN` parses that snapshot through a strict typed schema and preserves, for every group:

- original ordinal;
- original display name and emoji;
- default enabled state;
- default outbound intent;
- `rule_set_build_in`;
- `domain_suffix`;
- `domain_keyword`;
- `ip_cidr`;
- Android `package`;
- `processName`.

The loader requires exactly 28 groups and exactly six default-enabled groups. Unknown JSON fields are rejected so upstream schema drift cannot be silently ignored.

## Layer semantics

All 28 groups remain L1 custom-group source material even when a group references `geosite:*`, `geoip:*`, or `acl:*`.

For example, "国内直连" remains one custom group containing its seven ACL references; its references are not split and moved into lower GeoIP/GeoSite/ACL layers.

## Target mapping

Only the three outbound values present in the pinned CN snapshot are accepted:

- `direct` -> typed DIRECT target;
- `block` -> typed BLOCK target;
- `currentSelected` -> typed CurrentSelected target.

Any new upstream target value fails closed until explicitly reviewed.

## What this stage does not do

The snapshot loader does not construct `domain.MatchExpr`.

In particular, it does not guess whether combinations of rule-set, domain, IP, package, and process fields are globally OR, globally AND, or grouped by field family. Linux platform pruning is also not performed here.

A later compatibility conversion stage must use executable fixtures to translate one snapshot group into the explicit boolean AST while ensuring unsupported package/process branches cannot collapse into an unconditional match.

## Upgrade consequence

Preset updates are treated as new immutable snapshots. A future updater must compare old upstream snapshot, new upstream snapshot, and user overrides before changing declarations. Restart or subscription update must never re-seed the six defaults over user choices.

## Capability

`cn_preset_snapshot=true` means the exact pinned preset source is available and validated.

`cn_preset=false` remains correct until semantic conversion, required rule-set resource closure, region auto-append behavior, declaration persistence, and actual routing fixtures are complete.


## Stable group identity

The upstream preset has no durable group identifier suitable for persistence. Ordinal-only IDs such as `cn-01` are not acceptable because an upstream insertion or reorder would silently retarget user overrides.

This project therefore assigns a reviewed semantic ID to each of the 28 pinned groups, including:

- `cn.ad-block`
- `cn.apple-services`
- `cn.google`
- `cn.openai`
- `cn.telegram`
- `cn.bilibili`
- `cn.domestic-direct`
- `cn.foreign-proxy`

The complete mapping is explicit in `cnStableGroupIDs` and is tested against the pinned group order.

These IDs are project persistence identity, not display names and not upstream data. A future preset upgrade must explicitly map old and new upstream groups to these stable IDs during the three-way upgrade preview; it must never regenerate IDs from the new ordinal.
