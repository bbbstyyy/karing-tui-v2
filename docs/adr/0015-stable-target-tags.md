# ADR 0015: Derive runtime outbound tags from stable target identity

- Status: Accepted
- Date: 2026-10-05

## Context

Route targets in the domain model are typed and stable, but sing-box requires string outbound tags. Display names, emoji, subscription labels, and source-provided tags are mutable and can collide across profiles.

Using them as runtime identity would make a rename alter compiled configuration references and could silently rebind a sensitive route.

## Decision

`internal/compiler.TargetCatalog` is the only route-target-to-outbound-tag resolver for the compiler stage.

Fixed symbolic targets use fixed internal tags:

- DIRECT -> `out-direct`
- CurrentSelected -> `out-current`
- Global URLTest -> `out-global-urltest`

Custom URLTest tags are derived from SHA-256 over the namespace `custom` and stable GroupID.

Specific Node tags are derived from SHA-256 over the namespace `node`, ProfileID, and NodeID.

The full digest is encoded in hexadecimal, so tag generation is deterministic and does not depend on input order or display text.

## Validation

Catalog construction rejects:

- duplicate custom group IDs;
- duplicate `(ProfileID, NodeID)` pairs;
- empty, whitespace-padded, overlong, or control-character stable IDs;
- invalid generated tags;
- any generated-tag collision.

Collision diagnostics are deterministic: map-backed entries are validated in sorted stable-ID order.

## Resolution behavior

A typed target resolves only if its stable identity exists in the catalog. Missing custom groups or nodes fail compilation.

BLOCK never resolves to an outbound tag because it is a route action, not an outbound.

The catalog intentionally creates identity only. It does not claim that a selector, URLTest group, or node outbound has been generated successfully. A later outbound compiler must materialize every tag required by `CompiledRouting.OutboundTags` and reject empty candidate groups or unsupported nodes.

## Stability consequence

Renaming a node, profile display label, country label, or URLTest display title does not change its runtime tag as long as stable IDs remain unchanged.

A genuine identity change produces a new tag and therefore cannot silently inherit a previous target binding.
