# ADR 0068: Credential-safe M3 profile management CLI

## Status

Accepted.

## Context

M3 source and node APIs existed behind a private Unix socket, but the single Go executable exposed no profile management command. Users otherwise needed to write their own HTTP client, and printing raw source API responses could accidentally expose token-bearing subscription URLs.

## Decision

Expose `karing-tui profiles` commands:

- `list [--json]`: only profile ID, revision, enabled state, format, accepted snapshot ID and last-success timestamp; never the source URL, User-Agent, fetch credential, or canonical node payload.
- `nodes <profile-id> [--offset=N] [--limit=N] [--json]`: request a bounded source-order page from the daemon. The client checks offset/limit limits before requesting the socket.
- `replace-overlay <profile-id> <node-id>` with an explicit CAS revision and **all** disabled/favorite/alias/sort-rank flags: a full replacement, not a patch with ambiguous default booleans. Use `--sort-rank=none` to clear the rank. Server-side CAS and node-existence validation remain authoritative.

CLI commands use the existing Unix-socket client. Read-only calls have a five-second deadline; overlay writes have a twenty-second deadline. No CLI command reads the SQLite database or writes native core JSON.

## Safety and consistency

A persisted overlay is user intent, not a declaration edit or core configuration apply. Even disabling a node does not auto-rewrite the active generation. A future explicit snapshot-to-declaration transaction must fail closed on missing selected references.

## Validation

Fake-client CLI tests cover safe JSON projection despite secret-bearing profile URLs, pagination validation before RPC, required complete overlay flags, revision propagation, clearing sort rank and rejected CAS writes.

## Remaining work

Usable profile source CRUD and explicit snapshot-to-declaration preview/promotion, selection testing and TUI screens remain separate milestones. This is not a full subscription compatibility claim.
