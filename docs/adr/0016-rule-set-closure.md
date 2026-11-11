# ADR 0016: Close rule-set references before native configuration emission

- Status: Accepted
- Date: 2026-10-05

## Context

The routing AST uses stable source references such as `geosite:cn`, `geoip:cn`, and `acl:ChinaDomain`. The approved sing-box 1.13.19 runtime does not consume those source references directly. Its `route.rules[].rule_set` field references runtime tags declared by `route.rule_set[]`.

The approved core supports local rule sets with:

- `type: "local"`
- a tag
- `format: "source" | "binary"`
- a path

The project plan also requires the compiler to operate only on immutable revision inputs and never fetch a mutable "latest" resource during compilation.

## Decision

`internal/compiler.RuleSetCatalog` binds source references to immutable artifact metadata:

- source reference;
- clean absolute path;
- SHA-256;
- exact format (`source` for `.json`, `binary` for `.srs`).

Runtime rule-set tags are derived as `rs-<sha256(source-ref)>`, independent of display text or local filenames.

The catalog computes only the closure actually required by `CompiledRouting.RuleSetRefs`, preserving first-use order and removing stable duplicates.

`BindRuleSetArtifacts` deep-copies compiled route rules and replaces source refs with runtime tags. The unbound routing result is left unchanged for diagnostics/source mapping.

## Fail-closed behavior

Binding fails if any required reference is missing.

Catalog construction rejects:

- duplicate source references;
- relative or non-clean paths;
- source/binary format mismatches with `.json` / `.srs`;
- malformed SHA-256 values;
- empty, padded, overlong, or control-character source references.

Extra catalog artifacts are not pulled into a generation merely because they exist.

## No network or filesystem reads in the compiler

This stage validates metadata only. It does not download a rule set and does not hash the file contents itself.

A later generation-artifact stage must verify that each referenced file at the fixed path matches the declared SHA-256 and then make the runtime resource set immutable for the generation.

That separation keeps the compiler deterministic while preserving a hard integrity gate before core `check`.

## Native output

Each closed artifact can render the exact local rule-set envelope needed by the approved core:

`{"type":"local","tag":"...","format":"source|binary","path":"..."}`

The whole-config emitter will consume these envelopes together with bound route rules. Until resource file verification/staging and full config assembly exist, `routing_ir` remains false.
