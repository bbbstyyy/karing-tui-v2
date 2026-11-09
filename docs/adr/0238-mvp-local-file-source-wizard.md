# ADR 0238: private local-file source creation from the TUI

Status: MVP-3 / MV-05 partial, internal Pre-MVP. Depends on confirmed
manual refresh from PR #120 and the protected profile source PUT endpoint.

## Decision

Allow the initial empty Profiles page to register a local-file source with
an explicit terminal wizard, without requiring manual runtime JSON edits.
The user enters a new ASCII source ID (up to 64 bytes), chooses one of
four strict importer formats, and enters an absolute, clean filesystem path
as seen by the daemon UID. The path is **never echoed or retained** after
confirmation. The UI only shows its byte count. The daemon stores the
configured path by design, subject to existing private state protections.

The wizard rejects unsafe/duplicate IDs, hidden/control characters, unknown
formats, relative/noncanonical/oversized file paths, small terminals, stale
or truncated source lists, and any attempt to overwrite an existing source.
An explicit `y` executes exactly one protected PUT with CAS
`ExpectedRevision=0`, `fetch.mode=direct`, no update schedule, no filter,
no remote URL, and `enabled=true`. It checks the complete PUT response,
then performs a separate bounded GET detail and list readback. It holds
only allowlisted IDs and numerical revision in the persistent model after
the operation. Ambiguous writes cannot be automatically retried.

Local source creation does not fetch/import nodes, mutate the declaration,
choose a node, apply/restart the Core, or grant rights to any CN rules.
The user must explicitly refresh (`u`), choose an accepted node, stage a
declaration, then perform a separate checked Apply. Leaving the wizard,
`Esc` or a terminal resize before confirmation discards the proposal.

## Release caveats

This slice does not enable remote URL entry, subscription authentication,
automated refresh, true CN 28-group live DNS, licensed rule distribution,
real restore or issue #59 resolution. All those remain MVP blockers.
Before merge require final SHA Go fmt/Vet/tests/build, Race 4/4,
managed native Core integration, amd64/arm64 provenance and explicit
negative tests for secret suppression and failed/CAS-conflict writes.
