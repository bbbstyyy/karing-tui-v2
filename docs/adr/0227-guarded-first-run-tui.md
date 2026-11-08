# ADR 0227: guarded first-run TUI initialization on Nodes page

Status: MVP-3 implementation candidate, not MV-05/MVP acceptance.

## Purpose

A new Linux user who has used the existing safe CLI source `put --stdin`
and `refresh` flow can inspect the accepted profile and nodes in the TUI
and stage the first source-derived proxy-only declaration without manually
editing native JSON or calling the HTTP API.

The existing Daemon first-run initializer (ADR 0225), first-run CLI (ADR 0226)
and checked Apply (ADR 0223) remain the sole authoritative validation and
mutation paths. This UI does not create a second configuration compiler.

## Interactive protocol

On the Nodes page, select a visible accepted, enabled node. Press `i` only
on an empty declaration/config-generation state with no recovery or active
operation. The UI requires a terminal at least 68x16. It captures the current
source revision, accepted snapshot ID, NodeID and the visible read tokens.
Typing an explicit DNS IP:port (IPv4 or bracketed IPv6), then Enter, requests
one **read-only** daemon `initial/preview`; the client never guesses a DNS
resolver. Unsafe characters, wildcards, multicast, zone-scoped addresses and
zero ports are rejected. No source URL or credential is rendered.

The preview dialog displays only identity/count, selected resolver and bounded
SHA-256 prefixes; it explicitly states `proxy-only-no-cn`,
`cn_rules_ready=false`, `core_validated=false`, `applied=false`.
Pressing `y` explicitly acknowledges that CN 28-group presets and complete
Karing routing/DNS are NOT present, and dispatches one bounded stage with the
exact snapshot, source revision, selected NodeID, DNS and candidate/overlay
digests. Escape, quit, resize or stale preview cancels without writing.

The Daemon's SQLite CAS remains authoritative if a source, overlay, snapshot,
declaration or applied generation changes between read and write. Even a valid
stage HTTP success is not announced as verified until a fresh bounded Status
readback confirms declaration revision one, zero config revision, no applied
or last-known-good generation and no recovery flag. On failure, timeout,
status mismatch or an inconsistent response, the TUI does **not** blindly
retry; it directs the user to inspect the declaration. Stage alone never
calls Core Check, Apply, stops/starts Core, or changes the applied generation.
Only the independent Dashboard `a` checked Apply command may request the
disruptive operation after another confirmation.

## Scope, threat boundary and evidence

The UI uses an optional typed first-run capability of the real Unix client,
so older read-only mock APIs remain compatible. Node list entries, profiles,
status and stage outcomes are bounded, and dynamic text passes through
terminal sanitization. The renderer never prints raw subscription fields,
daemon error bodies, credentials, or untrusted exceptions. Delayed
asynchronous preview messages must match the active sequence and identity.
Quit never implies cancellation of an already dispatched daemon write.

Unit tests cover explicit input, proposal and stage confirmation, no-RPC
invalid/preexisting states, wrong digest/node/revision and false CN-ready
preview, cancellation, late messages, resize and uncertainty safety.
The existing real-Core HTTP subscription integration tests cover the same
protected Daemon first-run API and are triggered for TUI changes too.
A full scripted human TUI → Core traffic test is still outstanding.

This slice is deliberately `proxy-only-no-cn`, not the required 28 Karing
CN groups or five-layer preset policy. It does not implement a full source
entry wizard, Clash/YAML, all protocol/TLS combinations, or real restoration.
It must not be marked MVP Beta. Keep Draft until exact-final-head format,
Vet, Go tests/build, four Race shards, pinned real Core integration and
Linux amd64/arm64 provenance all pass. The stable `main` remains unchanged.
