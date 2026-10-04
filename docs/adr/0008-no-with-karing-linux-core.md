# ADR 0008: Forbid with_karing in the daemon-managed Linux core

- Status: Accepted
- Date: 2026-10-05

## Context

The first successful 1.13.19 cross-architecture compilation used the `with_karing` build tag because Karing-specific files and extensions were being evaluated as part of the candidate.

On Linux, that tag changes the CLI root command to `cmd_extension_karing.go`. Its persistent pre-run function calls `makeProcessSingleton()`. The Linux implementation enumerates running processes, compares executable basenames, and terminates or kills another process when the basename matches.

That behavior is suitable only under assumptions made by the original app packaging. It is incompatible with this project's daemon ownership model.

## Decision

The daemon-managed Linux core MUST NOT be built with `with_karing`.

The reference build starts from the candidate's fixed `release/DEFAULT_BUILD_TAGS_OTHERS` and appends only `with_shadowsocksr`, which is required because the fork's registry imports the guarded ShadowsocksR implementation.

The provenance script fails closed if `with_karing` appears in the effective tag set.

## Rationale

The project promises that it will:

- never kill a process it did not start;
- never treat a basename match as ownership;
- fail on occupied configured ports rather than killing another listener or silently choosing a new port;
- keep core lifecycle under the daemon supervisor's process-group ownership.

Inheriting Karing's Linux singleton implementation would violate T19 and undermine all of those guarantees.

## Compatibility consequence

Karing-specific app service commands and extension-only control surfaces are not part of the M1 core contract. Karing behavior needed by this project must be implemented through the daemon's own state model, compiler, lifecycle coordinator, and verified standard Clash/sing-box interfaces.

This does not remove Karing compatibility goals. It separates behavioral compatibility from unsafe app-process lifecycle behavior.

## Evidence retention

Provenance run #5 produced amd64 and arm64 binaries with `with_karing`; their hashes remain in `resources/core.lock.json` under rejected/unsafe evidence and MUST NOT be promoted as release hashes.
