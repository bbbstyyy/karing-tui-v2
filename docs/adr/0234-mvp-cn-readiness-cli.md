# ADR 0234: guarded operator CN readiness CLI

Status: MVP-2/MVP-3 partial, Pre-MVP. Depends on #115 read-only
CN readiness API and pinned 28-group source inventory.

## Decision

Provide `karing-tui config cn-readiness [--json]` as an explicitly
read-only operator inspection. The command requires no root privileges,
uses the daemon's existing protected Unix socket, makes one bounded GET,
and never stages a declaration, installs a resource, downloads assets,
or authorizes Core Apply.

The dedicated client caps the HTTP body at 128 KiB before JSON decoding
and does not include server-provided text in parse errors. CLI transport
errors are sanitized, including token-bearing URLs or private file paths.
Unknown flags and all action-like arguments (`--apply`, `--enable`,
`--force`, etc.) are rejected before an RPC is sent. The command
uses a three-second context deadline.

Before printing anything, the CLI verifies that the untrusted daemon
response matches the embedded Karing preset snapshot. It compares the
exact source repository/commit/path, every ordered group ID/display
name/target/default enablement, all source condition family counts and
every referenced rule set. It also requires 68 logical references, 67
file-backed candidates, the two region append references and one
upstream-absent `geoip:bing`. Both the unresolved upstream license and
the missing-asset blockers must remain present and
`distribution_ready=false`. A fabricated "ready" response is rejected
rather than displayed as authorized.

The human view explicitly says NOT READY FOR APPLY OR REDISTRIBUTION
and lists all 28 groups. The JSON view carries the original bounded
readiness record. These are **source-inventory facts only**, not live
Core route or DNS observations, not proof of installed files or approved
redistribution rights. The CLI does not mutate the database or LKG.

## Test evidence and release limitations

Client tests cover the Unix-socket GET method, response byte ceiling,
single-read semantics and malformed JSON redaction. CLI tests check
normal and JSON output, all group lines, protected flags before RPC,
unavailable-daemon secret suppression and malicious reports (changed
source/condition, truncated/reordered group list, missing Bing, forged
license approval or distribution status).

This does not provide the actual licensed offline CN package, an
audited compatibility solution for Bing, CN group/DNS edit flow, a
real five-layer traffic/DNS proof, or restore and 72h stability
acceptance. MV-03/MV-04/MV-05/MV-07 remain release-blocking.
No TUN, subscription/ISP routing, automatic Core Apply, or changes
to stable `main` are made.

Merge only after #115 is merged and this PR is rebased to that final
development SHA. Revalidate Go fmt/Vet/test/build/integration compile,
Race 4/4, pinned Managed Core and linux-amd64/arm64 provenance
on the final PR head.
