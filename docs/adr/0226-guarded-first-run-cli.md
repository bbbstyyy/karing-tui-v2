# ADR 0226: CLI for guarded source-first initialization

Status: candidate for MVP-1 / MVP-3, not full MV-02/MV-05 or MVP acceptance.

## Motivation

An empty Linux installation can create an initial proxy-only V1 declaration
from an accepted source with the first-run daemon APIs introduced in ADR 0225,
but invoking these HTTP routes by hand is not a realistic user workflow.

Expose the two already guarded operations through the existing Unix-socket
CLI without changing the daemon's authorization, CAS or Apply semantics.

## User sequence

1. `karing-tui profiles put <id> --expected-revision=0 --stdin`, then
   `karing-tui profiles refresh <id> --expected-revision=N`. Supply source
   JSON via stdin: token-bearing URLs never belong in argv.
2. `karing-tui profiles nodes <id> --json` identifies the stable NodeID
   and the current accepted snapshot.
3. `karing-tui profiles init-preview <id> --snapshot-id=N
   --selected-node-id=ID --resolver=IP:PORT` returns an identity/digest-only
   preview; an explicit IP-literal DNS resolver is mandatory. Verify the
   `routing_mode=proxy-only-no-cn`, `cn_rules_ready=false` flags.
4. `karing-tui profiles init-stage <id> --snapshot-id=N
   --expected-source-revision=N --selected-node-id=ID --resolver=IP:PORT
   --candidate-sha256=HASH --runtime-overlay-sha256=HASH
   --acknowledge-proxy-only-no-cn` stages exactly that declaration once.
   This explicit acknowledgement cannot be omitted.
5. `karing-tui config apply-preview --out=PRIVATE_NEW_FILE` and then
   `karing-tui config apply --receipt=PRIVATE_FILE --confirm` remain
   distinct, existing explicit Core Check/Activate/Verify/Readback operations.

Both CLI commands validate profile/NodeID, resolver, flag completeness, hashes,
and response identity/mode before printing any acknowledgement. They never
print imported credentials or the constructed declaration, and they sanitize
untrusted transport/daemon error strings. An uncertain stage response is **not**
an invitation to retry: inspect current declaration/status first.

## Evidence and boundaries

The Unix-socket typed client is covered by a mock daemon that enforces the
actual HTTP paths, 200/201 response status, exact receipt and stale 409.
CLI tests verify no RPC on incomplete arguments, zero/unsafe resolver,
uppercase/invalid digest, missing explicit acknowledgement and replay-error
sanitization; fabricated CN-ready/applied responses cannot be called success.

The `managed-core-integration` workflow now also triggers on changes
to CLI, Unix-socket client, API contracts, profile-update and importer
code. This keeps the real Core flow gated when its user-facing entry
points change, rather than only when daemon or compiler files change.

The real Managed Core SOCKS5/HTTP flow is tested separately in PR #107, which
uses the same daemon first-run API instead of hand-seeding a declaration.
This PR does not itself introduce a TUI onboarding wizard, a CN preset/28
group resource closure, DNS policy parity, a second popular subscription
format, or validated Trojan/VLESS/Shadowsocks real upstream transport.
No TUN or subscription/ISP routing is enabled. Stable `main` stays untouched.

Merge only after an exact final head is checked: Go format/Vet/test/build,
four Race shards, real Managed Core Integration and Linux amd64/arm64 Core
Provenance. If stacked on PR #107, rebase on its eventual merge SHA and
reverify, never reuse an outdated green CI result.
