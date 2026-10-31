# ADR 0013: Lower explicit routing AST without using implicit sing-box field grouping

- Status: Accepted
- Date: 2026-10-05

## Context

The approved 1.13.19 core supports two route-rule shapes:

- default rules, whose field families have built-in mixed OR/AND semantics;
- logical rules with explicit `mode: and|or`, nested rules, and `invert`.

Because the project matcher IR already expresses boolean structure explicitly, packing several unrelated predicates into one default rule would reintroduce implicit sing-box grouping and could change meaning.

The fixed core source also confirms that a default rule with only an action is valid and matches as the catch-all rule. This gives FINAL one uniform representation, including BLOCK, without relying on an implicit first-outbound fallback.

## Decision

`internal/compiler.CompileRouting` lowers one explicit matcher atom into exactly one default-rule condition field.

- `all` becomes a logical rule with `mode: "and"`.
- `any` becomes a logical rule with `mode: "or"`.
- `not` toggles the candidate rule's `invert` flag.
- route targets other than BLOCK resolve through a typed target resolver to a generated outbound tag.
- BLOCK becomes `action: "reject"`.
- FINAL is emitted as the last explicit action-only catch-all rule.

The lowerer never sorts route groups or nested children.

## Dependency output

The lowerer also returns deterministic metadata:

- rule-set references in first-use order with stable de-duplication;
- generated outbound tags in first-use order;
- whether process lookup is required;
- a top-level rule-index source map containing layer, group, target, action, and outbound.

These are dependency requirements, not proof that resources or outbounds already exist.

## Fail-closed boundaries

A group with `DNSProfileID` is rejected for now. The compiler must not emit a route while silently ignoring the promised group DNS override.

Generated outbound tags are bounded and restricted to a stable ASCII identifier alphabet. Missing targets and unsafe tags fail compilation.

Rule-set references are only collected at this stage. A later resource-closure phase must resolve them to immutable artifacts before a generation can be checked or applied.

## Why routing_ir remains false

This lowerer is not yet the full native configuration compiler. Remaining gates include:

1. Karing flat-field compatibility conversion into the explicit matcher AST;
2. stable outbound/selector/URLTest generation;
3. immutable rule-set artifact closure;
4. DNS dependency graph and group DNS semantics;
5. three Mixed inbound emission;
6. deterministic whole-config JSON/source-map/manifest;
7. validation with the exact approved core before managed apply.

Only after those pieces are integrated can the daemon advertise `routing_ir=true`.


## Three-entry scoping

The lowerer also owns the route boundary between the three fixed Mixed inbounds.

Stable generated inbound tags are:

- Rule: `in-rule`
- Direct: `in-direct`
- Selected: `in-selected`

The emitted rule order starts with two synthetic terminal routes:

1. `in-direct` -> DIRECT target;
2. `in-selected` -> CurrentSelected target.

Every user five-layer rule is then wrapped in an explicit logical AND with `inbound: in-rule`. FINAL is an action-only catch-all **within `in-rule`**, not a global catch-all.

This prevents Direct/Selected traffic from falling into Custom/GeoSite/GeoIP/ACL/FINAL if the compiler grows additional inbounds later. Synthetic entry rules are infrastructure and are not presented as user route-source entries; source-map rule indexes still point at their actual positions after those synthetic rules.
