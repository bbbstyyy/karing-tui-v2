# ADR 0093 — Read-only bounded historical recovery evidence in TUI

- Status: **M4 observability only**; historical restore remains disabled.
- Dependencies: ADR 0084–0092.
- Scope: Linux normal-user HTTP/SOCKS operation, without TUN or subscription/ISP routing.

## Decision

Expose the existing `GET /v1/config/recovery/audit` as TUI page **9** (History), with manual `r` refresh, `j/k` scrolling and tab navigation. This is a read-only surface and never calls internal historical `core Check`, `PrepareHistoricalRestore`, `Activate`, `Rollback`, or any write API. No restore confirmation or hot-reload command exists.

Move the CLI recovery-audit response verification contract into the shared `apiv1.ValidRecoveryAudit` predicate, retaining its CLI wrapper for existing tests. Both clients reject unknown evidence/status/preflight values, impossible integrity flags, forged `restore_supported` or `restore_ready`, duplicate/unordered generations and more than 12 entries. A valid response merely establishes a bounded observation and never grants restore authority.

The model retains only numbers, booleans and allowlisted status strings. It does not cache native JSON, rule-set paths, raw SQLite errors or manifest contents. Calls are on demand with a 29-second client budget (server audit has a separate 25-second budget). Switching away cancels the request and clears state; sequence tokens reject late results. Oversized responses, RPC errors and failed validation render one generic message, never untrusted error text.

## Remaining gates

This UI neither solves durable activation/rollback resource leases nor proves live DNS/route readback. `restore_supported=false` and `restore_ready=false` remain mandatory. Production release still needs CN offline/license closure, protocol compatibility, historical restoration fault injection, and T15/T23/T25 evidence.
