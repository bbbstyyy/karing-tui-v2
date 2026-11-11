# ADR 0236: read-only CN source inventory in the terminal UI

Status: MVP-3 partial / Pre-MVP only. Depends on #115 and the reviewed,
merged #116 CN readiness CLI and its bounded Unix-socket client.

## Decision

Add a tenth TUI page, `[0]CN`. It requests exactly one GET from the
protected local daemon, within three seconds, using the shared bounded
client. A single common, complete validator checks all 28 group metadata
fields, original order, 6 source-default enabled switches, 68 refs / 67
candidate files, region append refs, upstream-missing `geoip:bing` and
unresolved license blockers. The CLI uses the identical validator.

Validation occurs before any daemon-provided string is projected into TUI
state. The screen stores only bounded allowlisted source group fields,
never raw daemon errors, subscription tokens, transport URLs or secrets.
Unknown, truncated, forged-ready and stale replies fail closed and cannot
be mistaken for a usable CN configuration. The request is read-only,
not an activation, DNS check, native Core test or proof of legal distribution.

The page is on-demand: `0`/Tab to open, `r` to reread and `j/k` to scroll.
A page departure cancels the request and invalidates late completions.
Ordinary navigation, quitting or write-shaped keys cannot stage a change.
The persistent help text always says CN is source-only and not ready.

## Boundaries and release blockers

The page does not add TUN, subscription/ISP routing, new resources,
rule-set fallback, or automatic application. No attempt is made to repair
missing upstream Bing rules with synthetic production files. The existing
five-layer model (Custom → GeoSite → GeoIP → ACL → FINAL), original CN
28-group semantics and provenance remain unchanged.

Real CN DNS/region runtime behavior, legally distributable and fully
verified offline assets, transactional backup/restore and #59, 72h
durability, and dual-arch installation still block MVP Beta. This PR
requires final-head Go fmt/Vet/unit/build, four race shards, Managed Core
integration and amd64/arm64 provenance. No claim of MV-03/04/05/07
acceptance is justified by a read-only page.
