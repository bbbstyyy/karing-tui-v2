# ADR 0012: Represent route matching as an explicit boolean AST

- Status: Accepted
- Date: 2026-10-05

## Context

The project must preserve Karing-style routing depth while removing the subscription/ISP routing layer. The fixed plan explicitly warns that Karing custom rule fields cannot be safely treated as globally OR or globally AND without compatibility fixtures.

The previous routing IR fixed layer order and typed route targets but intentionally deferred match semantics. Continuing directly from flat Karing fields to sing-box JSON would risk encoding an accidental boolean policy into the compiler.

## Decision

Route matching is represented as an explicit boolean AST before any sing-box lowering.

Supported operators are:

- `atom`
- `all`
- `any`
- `not`

Supported atom kinds are:

- exact domain
- domain suffix
- domain keyword
- domain regular expression
- canonical IP CIDR
- rule-set reference
- destination port/range
- network type (`tcp` / `udp`)
- process name

An enabled route group must have a matcher. A disabled group may keep no matcher or a retained matcher because it is omitted from active routing.

The AST is bounded to 32 levels and 4096 nodes. Regexes, canonical CIDRs, port ranges, rule-set identifiers, control characters, and unrelated predicate fields are validated before compilation.

## Why this comes before Karing compatibility conversion

This model does **not** decide how Karing's legacy flat fields combine. A compatibility importer must construct this AST from evidence and fixtures. For example, it may produce nested `all(any(...), not(...))` rather than relying on a compiler-wide default.

That separation prevents a future fix to Karing compatibility semantics from changing the core routing representation.

## Ordering consequence

The matcher is attached to the existing ordered `RouteGroup`. Flattening still preserves:

`Custom -> GeoSite -> GeoIP -> ACL -> FINAL`

and never sorts groups by matcher contents.

## Compiler boundary

This ADR does not yet make `routing_ir=true`. The next compiler stage must:

1. resolve typed route targets to stable generated outbound tags;
2. lower the explicit matcher AST to candidate-supported sing-box rule expressions without changing boolean meaning;
3. compute rule-set/DNS/outbound dependencies;
4. emit deterministic JSON plus source-map diagnostics;
5. pass the approved core's `check` before managed apply.
