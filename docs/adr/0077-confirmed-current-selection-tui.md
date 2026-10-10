# ADR 0077: Applied-generation CurrentSelected candidate picker and confirmation

## Status

Accepted as a bounded M4 slice. The TUI supports guarded selection updates, but remains incomplete for full group editing, routing, DNS, subscription and lifecycle workflows.

## Decision

`GET /v1/selection/current` includes `candidates`, `candidate_count` and `candidates_truncated`. The daemon obtains candidates from `selection.current.members` in **the same applied-generation-bound declaration** that validates the selected target; it does not use an unapplied current declaration if a generation is already applied. The list preserves source ordering and returns at most 128 typed target references. If the count exceeds 128, the response explicitly indicates truncation and the TUI disables mutations rather than implying it displays all candidates. This API exposes stable references, not node servers, passwords or imported subscription routing.

The TUI Selector page (5) shows persisted/default selection intent, live core readback and the typed candidate list. `j`/`k` moves the focus. `Enter` proposes a different candidate without writing, `y` explicitly confirms the proposal, and `Esc` discards it. The proposal captures all five `expected_*` CAS bindings from the GET read. The TUI only enables mutation when the list is complete and consistent, the applied generation ID is positive, and the declaration revision/SHA-256 is plausible. Stale results and page exits clear pending proposals. No implicit selection change occurs through candidate navigation, Tab, refresh or quitting.

`PUT /v1/selection/current/checked` runs only inside an asynchronous bounded Bubble Tea command; the UI allows one selection write in flight. Other keys (except UI quit) are blocked while a write is in progress. A success response must match the expected target and new selection revision, original config revision, applied generation, bound declaration and persisted state. Regardless of success or error, the TUI immediately discards its previous binding and GETs fresh daemon state before permitting another edit. A conflict (409) cannot be retried using stale input. A 502/timeout may follow a durable SQLite commit; no optimistic rollback is claimed and no automatic retry occurs. Raw daemon errors, runtime outbound tags and secrets do not enter persistent TUI state or terminal rendering.

The selection write **does not** automatically compile/apply declarations, restart the core, enable TUN, change CN 28 preset groups, add subscription/ISP routing, or alter unrelated groups. The existing daemon operation gate and SQLite CAS remain the concurrency authorities. Without a valid applied generation, the selector page is diagnostic only even though the lower-level API has a safe stopped-core pathway.

## Safety bounds

- At most 128 members and 256 bytes per member's stable ID field in the TUI.
- Candidate kinds restricted to specific node, Global URLTest and Custom URLTest; duplicate and mismatched candidate sets rejected.
- Three-second GET and ten-second checked PUT; no polling, background refresh or blind retries.
- UI errors are safe summaries; all displayed text uses the terminal sanitizer and viewport clipping.
- At most one pending confirmation or outstanding selection mutation; late read/write completions are ignored by sequence.

## Verification and remaining work

Tests cover the exact applied-versus-staged declaration, explicit candidate ordering and truncation, confirmation/cancellation, special group targets, concurrent 409, uncertain post-commit readback, inconsistent daemon responses, invalid/stale candidate lists, narrow-screen scrolling and no-unconfirmed writes. CI, Race Test and managed-core integration are required before considering this slice verified.

Full M4 still needs group/routing/DNS editing, backup/restore, diagnostics and robust long-running resource evidence. CN offline rule assets/license checks and M2/M3 compatibility gates remain open.
