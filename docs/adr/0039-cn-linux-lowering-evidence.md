# ADR 0039: Use last-public Karing builder evidence for conservative CN Linux lowering

- Status: Accepted
- Date: 2026-10-06

## Context

The pinned Karing application snapshot at `9d28b22fbbcca5818d147629aae151d49d4dcb7b` imports configuration-builder utilities that are absent from that public tree. ADR 0029 therefore preserved the CN preset without guessing how its flat fields were combined.

Git history shows that the missing public paths existed before they were removed in 2025. The last inspectable parent implementation is commit `e3c19f1eb1225dbd48a4862f0983b82d0af8de69`.

This historical implementation is older than the pinned 2026 application snapshot. It is evidence for compatibility fixtures, not authority to reproduce every old behavior blindly.

## Historical evidence

The last-public `DiversionRulesGroup` model initializes:

`bool or = true`

and loads missing `or` fields with the same true default.

The historical sing-box builder:

1. creates one child rule for each non-empty condition family;
2. includes domain suffix, domain, keyword, regex, IP CIDR, port, protocol, network, Wi-Fi, rule-set, and platform conditions independently;
3. emits a logical parent with mode `or` when the group's `or` value is true;
4. emits `package_name` only on Android;
5. emits process conditions only on PC platforms.

The pinned CN preset does not contain an `or` field. Therefore the historical public implementation interprets its field families as logical OR.

## Decision

`preset.LowerCNCustomRouting` provides a conservative Linux lowering for the immutable CN snapshot plus typed user overrides.

It preserves:

- all 28 stable group identities and original order;
- independent per-group enabled state, target, and DNS override;
- L1 Custom source identity even for `geosite:*`, `geoip:*`, and `acl:*` references;
- OR semantics across the supported condition atoms.

For Linux it lowers these pinned CN fields:

- `rule_set_build_in`;
- `domain_suffix`;
- `domain_keyword`;
- `ip_cidr`.

The Android-only `package` branch is omitted on Linux, matching the historical platform guard.

## processName boundary

The pinned CN JSON also has a legacy camelCase `processName` field in the WhatsApp, Telegram, and GitHub groups.

This ambiguity is visible even in the last-public historical sources: the 2025 CN preset already used camelCase `processName`, while the contemporary `DiversionCustomRule.fromJson` importer read snake_case `process_name` before copying its parsed value into `DiversionRulesGroup.processName`. That public snapshot therefore cannot prove that the camelCase preset field reached the Linux builder at all.

The pinned 2026 public tree no longer exposes the conversion path that may have corrected or otherwise changed that behavior. The older public model alone is not enough to prove the exact Linux mapping.

Therefore an enabled CN group carrying `processName` fails with a dedicated compatibility error. Disabled groups remain preserved as source state and do not need to be lowered until enabled.

This is intentionally stricter than silently discarding the process branch.

## Default CN consequence

None of the six pinned default-enabled groups contains `processName`.

Google Play additionally contains an Android package condition, but it also contains `geosite:google-play`; on Linux the historical builder omits only the Android package branch.

The default Linux active set can therefore be lowered without guessing platform process semantics. Tests require:

- exactly the six pinned default-enabled groups;
- stable order;
- the same first-use rule-set closure;
- OR semantics for multi-family groups;
- no Android package predicate in Linux output.

## Region append remains separate

The historical builder also provides useful evidence about region GeoSite/GeoIP insertion, but its insertion paths and auto-append guards are not fully symmetric. Because this code predates the pinned application snapshot, ADR 0030 remains the authority: region append is not compiled until the observed behavior is reconciled with the pinned UI/settings model and executable fixtures.

## Capability boundary

`cn_preset_linux_lowerer=true` means the conservative pure lowering above is implemented.

`cn_preset=false` remains correct. Full CN compatibility still requires:

- declaration persistence of the preset overlay;
- complete trusted/offline rule-set resources;
- resolved Linux `processName` compatibility;
- region auto-append lowering;
- actual routing fixtures against the approved core.
