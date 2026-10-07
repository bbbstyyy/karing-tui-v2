# ADR 0053: Routing mode and private-direct policy use an advertised internal Clash mode set

## Status

Accepted.

## Context

The public daemon contract exposes three routing modes: `rule`, `global`, and `direct`. Karing also has an independent `privateDirect` policy. The pinned core matches route rules with `clash_mode`, but its Clash API does not derive the set of accepted modes from route rules.

At the pinned core revision `beddeababcc71dfb0c78124598b13341c06c69fb`, the Clash API server initializes its accepted mode set from `experimental.clash_api.mode_list`. `SetMode` ignores a value that is not present in that list. The `/configs` response exposes the same list. Therefore, emitting route rules for a custom mode without advertising that mode does not create a usable runtime mode.

Karing source evidence for `privateDirect` places private-address DIRECT handling after ordinary diversion rules and before FINAL in Rule mode, while Global mode keeps private-address DIRECT behavior when the option is enabled. The daemon must also be able to toggle the option without recompiling or restarting the core.

## Decision

The daemon persists routing policy as one atomic intent:

- public mode: `rule | global | direct`;
- `private_direct: bool`.

The compiler emits two internal-only Clash modes in addition to the public names:

- `RuleNoPrivate`;
- `GlobalNoPrivate`.

The generated Clash API configuration must advertise this exact internal mode set:

1. `Rule`
2. `RuleNoPrivate`
3. `Global`
4. `GlobalNoPrivate`
5. `Direct`

The daemon maps its public policy to those core modes:

| Public policy | Core mode |
| --- | --- |
| Rule + privateDirect=true | Rule |
| Rule + privateDirect=false | RuleNoPrivate |
| Global + privateDirect=true | Global |
| Global + privateDirect=false | GlobalNoPrivate |
| Direct + either value | Direct |

`Direct` does not need a second core mode because the Rule entry is already forced DIRECT; the persisted `private_direct` preference is retained for a later switch back to Rule or Global.

The generated route order keeps private-address behavior explicit:

- dedicated Direct and Selected inbounds remain first and are independent of Rule-mode policy;
- Global/privateDirect uses an `ip_is_private` DIRECT rule before the Global catch-all;
- normal five-layer Rule groups run before the Rule/privateDirect rule;
- Rule/privateDirect runs before FINAL;
- `RuleNoPrivate` and `GlobalNoPrivate` omit the private-address rule by selecting a mode that does not match it.

Proxy DNS pre-resolution must not treat the Global private-address DIRECT rule as a proxy-target Global catch. Only the CurrentSelected Global/GlobalNoPrivate catch rules receive proxy DNS resolution.

The external daemon API continues to expose only `rule`, `global`, `direct`, and `private_direct`. Internal mode names are an implementation detail and are not user-selectable through the public API.

## Consequences

This preserves immediate live switching for `privateDirect` without rewriting a generation or restarting the core. The persisted intent and live core state can be read back independently, so failed live updates remain visible instead of being reported as successful.

Core upgrades must verify both of the following before compatibility is claimed:

1. custom `clash_mode` route rules still compare against the current Clash API mode;
2. `experimental.clash_api.mode_list` still controls the accepted values for `SetMode`.

Managed-core integration tests must exercise Rule/Global privateDirect on/off behavior, L1 precedence, Direct/Selected bypass semantics, and restart restoration against the pinned executable.
