# ADR 0011: Encode the five-layer routing order before compiling match expressions

- Status: Accepted
- Date: 2026-10-05

## Context

The project must preserve Karing-style routing depth without reintroducing subscription/ISP routing. The required runtime order is:

1. Custom;
2. GeoSite;
3. GeoIP;
4. ACL;
5. FINAL.

Ordering is behavior. A compiler that stores groups in an unordered map or silently sorts them by name, country, latency, or rule-set tag can change routing meaning.

At the same time, the exact boolean semantics for all Karing match fields still require compatibility fixtures. Encoding those expressions prematurely would risk baking guessed OR/AND behavior into the domain model.

## Decision

The first routing IR increment models only the parts whose semantics are already fixed by the plan:

- four ordered group layers plus one explicit FINAL target;
- globally stable group IDs;
- a persisted order value whose sequence must already be strictly increasing within each layer;
- explicit enabled/disabled state, where disabled/NONE is not a route target;
- typed targets: DIRECT, BLOCK, CurrentSelected, Global URLTest, Custom URLTest, and Specific Node;
- typed identifiers for custom URLTest groups and specific nodes;
- optional per-group DNS profile reference;
- fixed flattening order that never performs a hidden sort.

The model structurally has no subscription or ISP layer.

## Validation policy

The IR rejects:

- duplicate group IDs across layers;
- duplicate or descending order values inside a layer;
- a group stored in the wrong layer;
- missing or malformed typed target identities;
- a magic `none` target;
- a missing FINAL target;
- DNS binding on a BLOCK target.

A disabled group may retain a valid previous target binding so toggling it off does not destroy user configuration, but it is omitted from active route steps.

## Deferred semantics

This ADR does not define the complete matcher expression language. Domain/suffix/keyword/regex/IP/rule-set/port/network/process boolean composition remains pending compatibility work.

It also does not compile sing-box JSON. Rule-set resource closure, selector dependency graphs, DNS binding semantics, source maps, and final adapter emission are separate steps.

Accordingly, the daemon advertises `routing_ir_model=true` but keeps `routing_ir=false` until the validated model can be deterministically compiled and checked by the approved core.
