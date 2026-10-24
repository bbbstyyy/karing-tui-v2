# ADR 0018: Materialize CurrentSelected and URLTest as an acyclic outbound graph

- Status: Accepted
- Date: 2026-10-05

## Context

The P0 routing model can target CurrentSelected, Global URLTest, Custom URLTest, or a Specific Node. These are routing targets, but the approved core needs concrete selector/urltest outbounds with candidate tags.

The plan requires independent automatic groups, stable candidate order, explicit test settings, no silent DIRECT fallback, and cycle detection. It also notes that CurrentSelected may point at supported automatic groups, while URLTest groups represent node candidate sets.

## Decision

The selection model is intentionally two-level:

- CurrentSelected candidates may be Specific Node, Global URLTest, or Custom URLTest.
- Global and Custom URLTest candidates may only be Specific Node.
- CurrentSelected cannot contain CurrentSelected.
- URLTest groups cannot contain selectors or other URLTest groups.

This makes the P0 selection graph acyclic by construction rather than depending on a late recursive cycle detector.

## URLTest policy

Every materialized URLTest group requires explicit:

- HTTP/HTTPS test URL without URL userinfo;
- positive interval;
- positive tolerance;
- positive idle timeout.

The compiler does not rely on the core's implicit URLTest defaults. Candidate arrays are never sorted; declared order is preserved.

The model also preserves the explicit `interrupt_exist_connections` behavior. Its zero/default value is false, matching the product requirement that selection changes do not normally terminate existing connections.

## Runtime closure

`CompileSelectionGroups` consumes the ordered outbound-tag closure already produced by routing.

It then:

1. records any directly referenced Specific Node dependencies;
2. resolves CurrentSelected candidates in declared order;
3. adds URLTest groups referenced either by routing or CurrentSelected;
4. adds each required URLTest group's node candidates;
5. de-duplicates node dependencies without reordering first use;
6. emits required URLTest outbounds before the CurrentSelected selector.

Unused URLTest groups are not emitted and therefore do not generate background probes.

## Failure policy

Compilation fails if:

- a route requires an unknown outbound tag;
- Global URLTest is referenced but absent;
- a Custom URLTest tag has no corresponding configured group;
- any node candidate is absent from the stable target catalog;
- a selection group is empty or has duplicate candidates;
- CurrentSelected's default is not one of its declared candidates.

There is no automatic fallback to DIRECT, a different country, or another subscription.

## Native mapping

The approved core shapes are emitted directly:

- selector: `type/tag/outbounds/default/interrupt_exist_connections`
- URLTest: `type/tag/outbounds/url/interval/tolerance/idle_timeout/interrupt_exist_connections`

The Karing-only URLTest extensions are not enabled at this stage because their required behavior has not yet been established for this product.

## Remaining boundary

The result still references node outbound tags. A protocol-specific node compiler must materialize every required node tag before whole-config emission. Until that, selector/URLTest closure is verified but not yet a complete runnable generation.
