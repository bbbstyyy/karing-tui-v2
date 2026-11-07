# ADR 0049: Persist typed CurrentSelected intent and verify live selector updates

- Status: Accepted
- Date: 2026-10-07

## Context

CurrentSelected is a symbolic routing target, not a permanently fixed node.
Changing it must affect new connections immediately when the core is running,
survive daemon/core restarts, and remain tied to stable domain identities rather
than generated runtime tags.

The approved KaringX/sing-box baseline exposes Clash-compatible selector
endpoints. A selector update alone is insufficient for durable behavior:
runtime state is lost when the core restarts. Conversely, rewriting a complete
configuration generation for every selection click would conflate a lightweight
runtime choice with structural configuration apply transactions.

The declaration store can also be ahead of the applied generation. A user may
commit declaration revision N+1 while generation N is still serving traffic.
Selection validation therefore cannot blindly use the newest declaration.

## Decision

SQLite schema version 6 adds a singleton `selection_state` row. It stores the
canonical JSON representation of the selected typed `TargetRef` and its update
timestamp. It does not store the generated outbound tag.

A selection request is validated against the declaration bound to the currently
applied generation. The binding is resolved from the generation manifest's
`declaration_revision` and `declaration_sha256`, with the persisted manifest
hash verified before it is trusted. Only when no applied generation exists does
the control plane use the current declaration as the future configuration
context.

The daemon exposes:

- `GET /v1/selection/current` for durable intent plus live readback;
- `PUT /v1/selection/current` with a typed target.

The client sends typed targets. Internal runtime tags remain an implementation
detail.

When the core is running, PUT performs this sequence:

1. validate the typed target is a member of CurrentSelected in the applied
   declaration;
2. persist the typed intent;
3. resolve its stable runtime tag;
4. PUT the tag to the pinned core's `/proxies/out-current` selector endpoint;
5. GET the selector and require both membership in `all` and exact `now`
   readback.

The pinned core returns selector JSON with `text/plain; charset=utf-8`; the
client accepts either `application/json` or `text/plain`, while still
enforcing response-size limits, strict JSON decoding, loopback-only authenticated
control access, redirect refusal, and exact semantic readback.

If the core is stopped, PUT persists the intent without claiming it is already
applied.

## Restart and apply recovery

Persisting intent alone does not change an already stored generation's selector
default. Therefore ManagedCore restores the selector after starting a generation
and while verifying a candidate generation.

Restoration is generation-specific:

1. load the exact generation manifest;
2. read its bound declaration revision and hash;
3. load that declaration;
4. resolve the persisted typed target in that declaration;
5. apply and read back the selector update.

This restoration runs for normal Start, crash/recovery reconciliation, candidate
Verify, and Rollback when the core is expected to remain running. It never uses
a newer unapplied declaration to reinterpret an older generation.

If a persisted selection exists but the generation has no trustworthy
declaration provenance, restoration fails closed. A core that was just started
with an unverified selection is stopped rather than left serving traffic through
the wrong default target.

A new declaration that removes the persisted target cannot silently replace the
healthy generation: selection-aware compilation fails until the intent is made
valid for the new declaration.

## Failure behavior

Persistence happens before the live selector update. If the core update or
readback fails, the API reports a live-update failure and retains the durable
intent. This makes the desired state explicit for diagnosis and future recovery
instead of silently reporting success.

The API reports `applied=false` when the core is stopped or when live readback
does not equal the resolved durable target.

Selection changes never create a new configuration revision or generation.
Structural declaration/apply transactions remain separate.

## Validation

Unit and race coverage verifies:

- selection intent persistence across SQLite reopen;
- strict typed target membership validation;
- real compiler override of `out-current.default`;
- selector PUT followed by GET readback;
- validation against the applied declaration when a newer declaration is only
  committed;
- generation-provenance restoration during Start and candidate Verify;
- fail-closed startup when persisted intent cannot be mapped to generation
  provenance.

The managed-core integration test uses two distinct local HTTP proxy nodes. It
observes Selected traffic on proxy A, switches CurrentSelected to proxy B,
observes new traffic on B, stops the core, starts the same applied generation,
and observes traffic still on B. This runs against the pinned
KaringX/sing-box binary in CI.

## Consequences

The capabilities `current_selection_intent`, `current_selection_api`, and
runtime-dependent `current_selection_live` are now backed by durable and
observed behavior.

This ADR covers CurrentSelected only. Complete group list/show/select UX,
subscription-derived node identity, dynamic tag/regex groups, URLTest outcome
coverage, and connection-interruption policy remain separate work items.
