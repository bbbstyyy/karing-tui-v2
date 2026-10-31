# ADR 0014: Scope five-layer routing to the Rule inbound

- Status: Accepted
- Date: 2026-10-05

## Context

The product has three fixed loopback Mixed entrypoints with different semantics:

- Rule: evaluate the five-layer routing plan;
- Direct: bypass the five-layer plan and use DIRECT;
- Selected: bypass the five-layer plan and use CurrentSelected.

A global FINAL rule would be dangerous even if Direct and Selected rules currently appear before it. Future non-terminal preprocessing or new inbounds could allow traffic to reach that catch-all.

## Decision

Inbound runtime tags are stable compiler identifiers and do not derive from display names:

- `in-rule`
- `in-direct`
- `in-selected`

The route lowerer emits Direct and Selected terminal routes before all user routing rules. Every Custom/GeoSite/GeoIP/ACL rule is explicitly scoped to `in-rule`, and the final catch-all is also scoped to `in-rule`.

The compiler does not silently substitute a port or tag. Ports remain the validated `InboundSet` values; tags are fixed internal identifiers.

## Source-map consequence

The two synthetic entry rules are not user-authored routing groups, so they do not create user route source-map entries. User group and FINAL entries keep their actual generated rule indexes, including the two-rule synthetic prefix.

## Failure policy

Compilation resolves DIRECT and CurrentSelected targets up front. If the Selected target cannot be resolved, configuration generation fails rather than silently turning the Selected port into DIRECT or falling through to Rule routing.
