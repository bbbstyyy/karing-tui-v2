# ADR 0035: Version declaration documents before exposing daemon configuration writes

- Status: Accepted
- Date: 2026-10-06

## Context

The daemon already stores immutable declaration revisions and the declaration compile coordinator verifies revision integrity before handing bytes to a compiler. What is still missing is a safe public boundary for creating those revisions and proving that a stored declaration can be lowered through the real compiler without bypassing the apply journal.

Accepting arbitrary native sing-box JSON would undermine the project model, allow unsupported privileged features to re-enter the runtime, and make declaration provenance meaningless. A declaration API therefore needs a project-owned schema with fail-closed validation.

## Decision

The first public declaration format is `schema_version: 1`.

`POST /v1/declaration` accepts an expected declaration revision, a bounded source label, and the declaration JSON document. Before SQLite commit, the daemon parses the document with unknown-field rejection, converts it into the existing domain model, validates the routing/selection/node/DNS closure, and runs the semantic compiler pipeline. Only a document that is compilable by schema v1 can become the new immutable declaration head.

`GET /v1/declaration/current` returns the current immutable declaration revision and its exact stored JSON.

`POST /v1/declaration/compile` compiles an explicitly requested stored revision through `DeclarationCompileCoordinator`. The response is a preview containing only artifact identity and closure metadata (schema/config hashes, tags, route count, rule-set count). It does not return native config JSON or the core control secret and it does not create or apply a runtime generation.

## Schema v1 scope

Schema v1 deliberately exposes only already-modeled safe concepts:

- log level;
- basic HTTP and SOCKS nodes;
- CurrentSelected, global URLTest and custom URLTest declarations;
- Custom -> GeoSite -> GeoIP -> ACL -> FINAL routing with the explicit boolean match AST;
- bootstrap/outbound/direct/proxy/group DNS roles supported by the current compiler.

The three Mixed inbound addresses/ports and the authenticated core control plane remain daemon-owned runtime settings. They are not declaration fields.

Rule-set references are rejected in schema v1 until daemon-owned resource resolution can bind a declaration reference to an immutable, verified, content-addressed rule-set artifact. Fallback DNS remains rejected by the existing compiler until its semantics are implemented. Unknown JSON fields and unsupported enum values fail closed rather than being silently ignored.

## Apply separation

A successful compile preview does not mutate the running generation. The next apply API must explicitly compose:

`stored declaration revision -> integrity check -> schema compiler -> provenance binding -> ApplyNativeArtifact`

and must require the caller's expected runtime config revision so the existing apply-journal CAS and rollback rules remain authoritative.

## Consequences

This creates the first versioned user configuration surface without creating a second configuration path. Stored declarations are guaranteed to be syntactically and semantically understood by the daemon version that accepted them, while actual runtime activation remains a separate, recoverable transaction.
