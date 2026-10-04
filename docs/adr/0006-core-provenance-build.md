# ADR 0006: Reproduce the standalone Linux core from fixed upstream workflow evidence

- Status: Accepted
- Date: 2026-10-04

## Context

The selected KaringX/sing-box commit cannot be built from an isolated checkout because its `go.mod` contains six local `../../KaringX/...` replacements. Earlier audit work locked those sibling commits, but the build was still treated as blocked by two facts in the Makefile: its default tags omit `with_karing`, and its version helper is invoked with `@latest`.

The fixed repository also contains an upstream GitHub Actions build workflow. That workflow is a better source for the standalone Linux CLI build contract than the generic Makefile target.

## Evidence

At `KaringX/sing-box@9f020fcefd4c9655689d503abd11572f31365b5a`, `.github/workflows/build.yml`:

- sets up Go 1.26.7;
- has Linux amd64 and arm64 purego matrix entries;
- uses `CGO_ENABLED=0`;
- loads `release/DEFAULT_BUILD_TAGS_OTHERS` for non-Naive purego builds;
- loads `release/LDFLAGS`;
- builds `./cmd/sing-box` with `-trimpath` and an empty build ID.

The Karing-specific extension files are guarded by `with_karing`, but that tag is not added to the standalone Linux reference build.

## Decision

The first Linux core for this project follows the fixed upstream standalone pure-Go path rather than attempting to reproduce the Karing Flutter app's local `vpn-service`/FFI packaging.

This is valid for the project architecture because our daemon owns:

- core lifecycle and restart policy;
- configuration generation/application/rollback;
- local API authentication and readiness;
- routing/domain state and the future TUI API.

The first standalone core therefore does not require Karing's optional app-specific extension endpoints. If a later compatibility feature requires one of those endpoints, `with_karing` becomes a separately tested capability rather than silently changing the baseline build.

The verification script:

1. checks Go 1.26.7 exactly;
2. recreates the required KaringX workspace layout;
3. fetches the core and six sibling forks at exact commits;
4. verifies each sibling module path;
5. verifies that build tags and shared ldflags still match the lock file;
6. builds Linux amd64/arm64 purego with a fixed linker version instead of the Makefile `@latest` helper;
7. prints SHA-256 for later lock-file recording;
8. executes `version` on the native amd64 artifact.

No artifact is published by this workflow.

## Approval boundary

A successful build is necessary but not sufficient for `build_approved=true`. Approval additionally requires recorded hashes and runtime checks for ordinary-user execution, configuration validation, authenticated local Clash API, expected loopback Mixed listeners, and the project's no-TUN configuration restrictions.

The fixed `PUT /configs` behavior remains explicitly non-reload evidence; managed configuration application continues to use controlled process activation and rollback.
