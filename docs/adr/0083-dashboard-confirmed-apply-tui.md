# ADR 0083: Explicit checked apply confirmation on Dashboard

- Status: Accepted as a bounded M4 TUI interaction.
- Scope: Linux unprivileged daemon client, no TUN, no subscription/ISP routing layer.

## Motivation

M4 already has `config apply-preview` and `config apply --receipt --confirm`, with independent immutable declaration hashes, runtime revision/generation and CurrentSelected revision guards. The TUI Routing editor deliberately stages without activating. The operator needs an interactive route from staged declaration to a **separately confirmed** core apply, without silently treating an edit preview as an activation.

## Decision

The Dashboard (page 1) uses `a` to asynchronously call the existing `GET /v1/config/apply/preview`. This is a strict compiler preview of the current unapplied declaration, not a real core check and not a write. The TUI accepts only a v1, compiler-validated, unapplied response with lower-case SHA-256 digests, positive declaration revision, bounded schema text and nonnegative resource counts. It additionally compares current Dashboard declaration/config revisions and applied-generation identity to the receipt, while relying on the daemon to verify the authoritative selection revision and declaration SHA.

The confirmation screen lists current declaration/config revisions, applied generation, CurrentSelected revision, truncated display-only digests, native schema and bounded route/DNS/rule-set counts. It warns that applying may restart the managed core and interrupt connections. `y` sends exactly one confirmed mutation, `Esc` cancels without mutation and `q` quits without confirming. The screen requires at least 64 columns and 16 rows: a shrink discards any pending confirmation, rather than allowing a blind keystroke. New status refresh or page navigation invalidates late preview responses.

On explicit `y`, a bounded command calls `POST /v1/config/apply/confirm`; the daemon performs its existing guarded strict recompile, core check, activation, verification, journal commit or failure rollback. The TUI does not automatically issue a second apply on timeout, error or invalid response. It checks the exact declaration/native SHA and schema, attempt/generation IDs, before/after config revision and positive core validation flags. It then attempts a bounded `GET /v1/status`, compares the committed config revision and applied-generation identity, suppresses any raw core error payload and reports either **verified** or **uncertain**. Status alone without a valid acknowledgement cannot turn an uncertain apply into success.

While a confirmed apply is in flight, the TUI blocks all other keyboard mutations except `q`; quitting ends the TUI, not the daemon. A previously accepted daemon apply can finish after disconnection, so no local rollback is assumed.

## Explicit exclusions

This is **not** a historical revision/generation chooser, not a user-triggered rollback endpoint, not a consistent backup, not a core/DNS packet-path parity test, and not an M4/M5 completion claim. It uses the same checked current-head endpoint as CLI. FINAL and generated region routing restrictions, pinned CN preset, five-layer routing order, no TUN and subscription/ISP routing exclusion remain unchanged. Manual recovery UX, durable backup, DNS detour observation, resource/licensing closure and long-run reliability gates stay open.
