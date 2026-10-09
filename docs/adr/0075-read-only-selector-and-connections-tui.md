# ADR 0075: Read-only CurrentSelected and bounded connection evidence in TUI

## Status

Accepted as an incremental M4 client-only capability, not a complete selector editor or connection manager.

## Context

The daemon already supports a typed CurrentSelected GET with durable intent and live selector readback, and an observed core connection endpoint with independently simulated/unknown source attribution. Combining these evidence levels into one seemingly verified route outcome would misrepresent actual observations. The existing CurrentSelected PUT does not have a conditional selection revision / CAS. Exposing a read-then-write action from the TUI could overwrite concurrent decisions.

## Decision

Introduce TUI pages 5 Selector and 6 Connections, both strictly read-only over daemon-owned Unix socket APIs. Query on entry or manual r; no polling, retries, background streams, core lifecycle mutation or connection-close action. Each query is limited to three seconds, with one request in flight per page. Responses are sequence-checked and abandoned when leaving their page; stale data and raw errors never reach the UI.

Selector shows only stable typed target identity, whether intent is explicitly persisted or comes from the bound declaration default, and a live readback classification: matches / mismatched / not observed. Runtime tags, credentials and untrusted upstream errors are not retained. Contradictory applied=true metadata is rejected.

Connections displays exact observed applied generation and configuration revision, transfer counters, up to 30 sanitized row summaries and total row count. Core connection metadata has evidence=observed; source layer/group, typed target and DNS-profile binding are shown only with source[SIMULATED], or else source[UNKNOWN]. A DNS binding is not observed DNS activity. The TUI does not retain process paths, user names, source IPs, connection IDs, raw rule payloads, chains or credential-bearing URLs. Destination domains/IPs are strictly parsed. Unknown reasons are allowlisted categories and never echo opaque source content.

The Unix socket client now limits the connection response size before JSON decoding. A response exceeding eight MiB, a mismatched evidence class, or a malformed selector readback is reported as unavailable, not silently converted to a healthy state.

Neither new page can mutate selection, core, routing, DNS, declarations or persistence. Overlay edits remain separately confirmed. Until the daemon provides an atomic checked selection update tied to the applied declaration identity and persisted intent revision, no TUI selection write control will be exposed.

## Validation

Tests cover asynchronous/manual refresh, default vs persisted intent, live selector mismatch, unsupported evidence, a 30-row retention cap, untrusted credentials and control sequences, stale completions, narrow terminals, and bounded HTTP response size. CI requires format/vet/unit/race/build and approved-core integration.

## Open follow-ups

1. Implement an atomic selection revision/CAS API with applied-generation binding, conflict responses, and persistence/live-readback uncertainty semantics before introducing confirmed selector edits.
2. Consider paged, server-redacted connection summaries for high concurrency rather than retaining entire core connection JSON in the TUI.
3. Continue CN offline resource/license closure and full M2/M3 protocol/DNS compatibility and long-duration stability gates.
