# ADR 0017: Stage rule sets into a private content-addressed runtime store

- Status: Accepted
- Date: 2026-10-05

## Context

The compiler already closes logical rule-set references against immutable revision metadata, but metadata alone is not enough for a running core. A source path may refer to a package asset, import cache, or downloaded staging file that can change independently of the configuration transaction.

The apply journal fixes the final native configuration bytes before it allocates a generation ID. Therefore a design that first prepares the config and later rewrites it to generation-specific rule-set paths would invalidate the stored configuration hash.

## Decision

Rule-set bytes are staged before whole-config emission into a daemon-owned content-addressed store:

`<core-state>/rule-sets/sha256/<sha256>.<json|srs>`

The path is independent of generation ID and is determined only by the validated content hash and format. Multiple generations may safely reference the same immutable content.

`coreartifact.Store.StageRuleSet`:

1. requires a clean absolute source path and `.json` or `.srs` extension;
2. opens the source with `O_NOFOLLOW` and requires a regular file;
3. copies and hashes through the same open file descriptor, preventing path replacement between verification and copy;
4. requires the copied bytes to match the manifest SHA-256;
5. writes the private copy as mode `0600`;
6. atomically publishes it under the content-addressed name;
7. fsyncs the content-address directory chain;
8. treats an existing mismatched content-addressed file as immutable-store corruption.

Package-provided source files may be root-owned or world-readable. Their trust is the pinned manifest hash, not ownership. The private runtime copy, however, must be owned by the daemon UID and inaccessible to group/others.

## Compiler boundary

`RuleSetArtifact` now separates:

- `SourcePath`: immutable revision input used for staging;
- `RuntimePath`: private content-addressed path used by native sing-box configuration.

`LocalConfig()` fails until `RuntimePath` has been bound. `BindStagedRuleSetPaths` requires every closed artifact to be staged and requires the runtime basename to equal the artifact SHA-256 plus its format extension.

This prevents the whole-config emitter from accidentally pointing sing-box at a mutable package/download path.

## Transaction consequence

The intended order becomes:

1. resolve exact rule-set metadata from the requested revision;
2. compute the active closure;
3. stage and verify every required artifact into the content-addressed store;
4. bind runtime paths;
5. emit deterministic native config and manifest;
6. persist the candidate generation and config SHA-256;
7. run the exact approved core's `check`;
8. continue through activate/verify/commit or rollback.

No network fetch occurs in these steps. Resource download/update remains a separate transaction that must produce trusted manifest metadata first.

## Remaining work

A generation manifest still needs to record exactly which content-addressed artifacts are referenced. The managed core must verify that manifest before `check`, start, and rollback. Whole-config emission and outbound/DNS compilation are also still open.
