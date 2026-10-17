# ADR 0053: Routing mode and private-direct policy use core-discovered internal Clash modes

## Status

Accepted.

## Context

The public daemon contract exposes three routing modes: `rule`, `global`, and `direct`. Karing also has an independent `privateDirect` policy. The pinned core matches route rules with `clash_mode`, but its accepted Clash API mode set is not configurable from JSON.

At the pinned core revision `beddeababcc71dfb0c78124598b13341c06c69fb`:

- `option.ClashAPIOptions.ModeList` is tagged `json:"-"`, so a generated config cannot set it directly;
- `box.go` replaces that field with `experimental.CalculateClashModeList(options.Options)`;
- `CalculateClashModeList` discovers mode names from route and DNS rules containing `clash_mode`;
- `Server.SetMode` ignores values that are not present in that calculated list.

Therefore, an internal mode is usable only if at least one compiled rule references its `clash_mode`.

Karing source evidence for `privateDirect` places private-address DIRECT handling after ordinary diversion rules and before FINAL in Rule mode, while Global mode keeps private-address DIRECT behavior when the option is enabled. The daemon must also be able to toggle the option without recompiling or restarting the core.

## Decision

The daemon persists routing policy as one atomic intent:

- public mode: `rule | global | direct`;
- `private_direct: bool`.

The compiler uses two internal-only Clash modes in addition to the public names:

- `RuleNoPrivate`;
- `GlobalNoPrivate`.

The daemon maps its public policy to core modes as follows:

| Public policy | Core mode |
| --- | --- |
| Rule + privateDirect=true | Rule |
| Rule + privateDirect=false | RuleNoPrivate |
| Global + privateDirect=true | Global |
| Global + privateDirect=false | GlobalNoPrivate |
| Direct + either value | Direct |

`GlobalNoPrivate` is naturally discovered from its CurrentSelected catch rule. `RuleNoPrivate` deliberately shares the ordinary Rule tree and has no reachable mode-specific route. To make the pinned core discover it without changing traffic, the compiler appends a synthetic `RuleNoPrivate` marker **after FINAL**. FINAL is always terminal, so the marker is unreachable; it exists only for `CalculateClashModeList`.

The generated route order remains:

- dedicated Direct and Selected inbounds first;
- Global/privateDirect private-address DIRECT rule before the Global catch-all;
- Global and GlobalNoPrivate catch rules;
- Direct mode rule;
- normal five-layer Rule groups;
- Rule/privateDirect private-address DIRECT rule;
- FINAL;
- unreachable RuleNoPrivate mode-discovery marker.

Proxy DNS pre-resolution must not treat the Global private-address DIRECT rule as a proxy-target Global catch. Only the CurrentSelected Global/GlobalNoPrivate catch rules receive proxy DNS resolution.

The external daemon API continues to expose only `rule`, `global`, `direct`, and `private_direct`. Internal mode names are an implementation detail and are not user-selectable through the public API.

## Consequences

This preserves immediate live switching for `privateDirect` without rewriting a generation or restarting the core. The persisted intent and live core state can be read back independently, so failed live updates remain visible instead of being reported as successful.

The marker is intentionally outside the source map because it has no user-visible routing source and cannot be selected before FINAL.

Core upgrades must verify all of the following before compatibility is claimed:

1. custom `clash_mode` route rules still compare against the current Clash API mode;
2. mode discovery still scans route/DNS `clash_mode` values;
3. `SetMode` still rejects modes outside the discovered list.

Managed-core integration tests must exercise Rule/Global privateDirect on/off behavior, L1 precedence, Direct/Selected bypass semantics, and restart restoration against the pinned executable.
