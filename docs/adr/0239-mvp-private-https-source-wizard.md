# ADR 0239: private HTTPS subscription creation in TUI

Status: MVP-3 / MV-05 partial, still Pre-MVP. Extends #121 local
source creation and #120 guarded manual refresh.

## Decision

`s` on the TUI Profiles page opens the same bounded, confirm-only source
wizard as local-file `c`, but strictly chooses `location_kind=url`.
It accepts only validated HTTPS URLs (scheme/host required, no embedded
username/password, no fragments, no opaque URLs), a new allowlisted ASCII
profile ID (up to 64 bytes), and one of four explicitly selected importer
formats: sing-box, clash-yaml, uri-list or uri-list-base64.

Like local-file source creation, the URL input is **never echoed**. The
terminal reveals only its byte length, and all transport errors are
discarded without showing private addresses or query tokens. Query tokens,
if present, are stored by the daemon in its private source specification:
never claim they are absent from persistent state. The TUI cannot embed
credentials in URL userinfo and refuses plaintext HTTP to reduce accidental
credential disclosure. Existing CLI/API compatibility is unchanged.

Only after `y` does the UI issue one protected PUT with
`ExpectedRevision=0`, `fetch.mode=direct`, `enabled=true`, no filter,
no recurring schedule. It verifies all fields of the PUT reply, then
does separate bounded GET detail and source-list readback. No optimistic
acceptance, replacement of an existing ID, auto-retry, automatic refresh,
selected node mutation, declaration stage or Core apply is allowed.
Cancel/resize discards private unconfirmed input.

Unit tests cover the HTTPS good path, all four importer choices, rejected
userinfo, fragments, HTTP/invalid hosts, masked secrets, explicit
confirmation and no write when cancelled. The native pinned Core still
requires its own explicit fetch, stage, apply and live packet verification.

## Invariants / remaining blockers

No TUN, no subscription/ISP routing layer, no CN resource fetching.
Licensed CN resource closure, real CN DNS/region traffic, restored
recoverability (#59) and full offline/72h validation still block MVP.

## Full-fidelity source-list readback

The first PUT and separate detail GET must match the entire source spec.
For the subsequent independent source-list GET, retain only an ephemeral
SHA-256 commitment to the exact source spec, never the HTTPS URL. Compare
this commitment with the complete list entry, demand exactly one matching
ID at revision 1 and no background refresh/snapshot. Clear the commitment
on success, mismatch and cancellation. A same-revision substitution of
location/query token, format, fetch route, filter or update schedule
must NOT report success, must NOT trigger automatic retry or Core Apply.
This remains a transport-level integrity guard, not authentication of
upstream subscription content.
