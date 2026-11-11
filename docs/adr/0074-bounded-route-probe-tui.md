# ADR 0074: Bounded TUI explanation of applied-generation routing and DNS bindings

## Status

Accepted as an M4 read-only diagnostic slice; not proof of complete M2 DNS or routing compatibility.

## Decision

Add a fourth Bubble Tea screen, **Route Probe** (`4` / `Tab`), backed exclusively by the existing daemon `POST /v1/route/explain` endpoint. The page is a *simulator of the exact applied-generation route artifact*, never an online connectivity check and never a reconstruction from the latest mutable declaration.

Use `e` to edit an ASCII hostname or literal IPv4/IPv6 address (253-byte cap; no credentials, URL strings, whitespace, control codes, scopes or IDNs), `Enter` to request a simulation, `t` to cycle the explicit Rule / Direct / Selected inbound, and `r` to repeat. No request is made until Enter or `r`. Each daemon query uses a 3-second deadline, with only one in flight. Editing and cross-page navigation cannot enqueue an unbounded backlog. Leaving the page discards any pending result.

The client only retains bounded allowlisted provenance: outcome/evidence, rule index, applied generation ID, config revision, manifest-bound declaration revision, routing mode, source layer/group, target and DNS profile binding, at most four unknown conditions and at most sixteen initial native trace rows plus a decisive row. No raw daemon/core errors, outbound server names, proxy credentials or entire response objects enter model state. The existing terminal sanitizer and viewport clipping remain mandatory for every line.

Unexpected evidence, decision or response/input/generation identity is reported as unavailable rather than displayed as a decisive route. Rule-set membership stays `unknown` when it cannot be proven; the UI never skips it to claim FINAL or DIRECT. Source and DNS bindings are **configuration provenance**, not traffic or resolver observations. The page explicitly says that an applied-at-query generation may differ from the current runtime or most recently staged declaration.

No TUN/TPROXY/system proxy changes, persistent mutations, core reload, outbound packet or resolver query are issued by this screen. The existing overlay CAS workflow and daemon lifecycle remain independent.

## Verification

Tests cover explicit asynchronous requests, domain/IP normalization, input validation, query context deadlines, source/DNS provenance, unknown rule-set semantics, trace/condition caps, Chinese/escape/viewport behavior, in-flight reentry suppression, stale response discard, redacted errors and response identity rejection. CI still requires format/vet/unit/race/build and managed-core tests.

## Open follow-up

Add read-only live connection attribution on a separate evidence-marked screen, with independent stale/unknown handling. Preserve current-selector safety and CN offline-license/resource closure as outstanding gates.
