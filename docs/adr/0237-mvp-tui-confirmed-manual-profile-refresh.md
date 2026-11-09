# ADR 0237: confirmed manual refresh of existing subscriptions from TUI

Status: MVP-3 / MV-05 partial, Pre-MVP. Does not complete import creation,
profile-to-declaration binding or CN production availability.

## Decision

From the existing Profiles view the user can propose one manual refresh with
`u`. The UI shows a non-credential-bearing confirmation; `y` runs one bounded
protected `POST /v1/profiles/{id}/refresh` with the source revision CAS
from a complete, previously read source inventory, `AllowEmpty=false`.
`Esc`, page departure, or reducing the terminal below 52x9 discards an
unconfirmed proposal. No I/O runs in the Bubble Tea Update method.

The handler blocks duplicate confirmations during the bounded 65-second
client operation, then performs one independent, bounded GET to check the
source revision and accepted snapshot ID. The UI never retains or displays
the original source URL, credentials, ETag, upstream error or diagnostics.
It holds only allowlisted profile IDs/revisions and numeric result summaries.
An inconsistent response, 409, timeout or ambiguous connection failure
requires human inspection and does not automatically retry.

Refresh is **snapshot-only**. It does not replace a declaration, activate CN
routing/DNS, rewrite persisted CurrentSelected, stop/start the managed Core,
or update the currently applied generation/Last Known Good. Subsequent
node staging and checked Apply remain separate explicit actions.

## Test and release boundary

Regression tests cover source revision CAS, opt-in confirmation, no implicit
`AllowEmpty`, one operation, readback matching, stale replies, failed/malformed
results, terminal resize, hostile IDs/secrets, disabled source refusal and
no implicit resubmission.

Required PR gates: final exact SHA gofmt/vet/test/build, four race shards,
managed-Core integration, native amd64/arm64 provenance. MV-05 remains
**partial**: protected TUI source creation and full first-run CN/DNS work,
real recovery and licensed offline closure remain blockers.
