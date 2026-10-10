# ADR 0078: Bounded, privacy-safe applied Routing/DNS inspection

## Status

Accepted as a read-only M4 inspection slice. Routing/DNS mutation, compiler-verified pre-apply previews and user-recoverable rollbacks are separate release-gated features.

## Context

The daemon already stores immutable applied generations and their declaration provenance, and has an explicit compile/apply transaction for declaration revisions. Feeding the full declaration into Bubble Tea would expose outbound node credentials, DNS server hosts and matcher values in model state or screen. A flat routing list would also conceal the CN preset's interleaving and automatically appended region groups. Merely reading a stored declaration cannot prove which rule or DNS resolver handled live traffic.

## Decision

Add `GET /v1/config/inspection`, a bounded **non-mutating** structural projection. It requires an applied generation and no active apply/recovery. It validates stored native config SHA-256, manifest SHA-256, native schema/config identity, generation-to-declaration binding and the bound declaration digest before parsing. A second daemon snapshot and declaration-head read rejects concurrent generation/head changes. Any missing/corrupt provenance returns a generic error without leaking raw declaration or DNS fields.

The daemon reuses `declaration.EffectiveRouting`, delegating to **the exact CN preset merge and region auto-append path used by compilation**. It emits the five fixed layers in priority order, including disabled groups and FINAL; preserves each group's ordinal, declared target, enabled state, DNS-profile binding and exact origin class (`custom`, `cn_preset`, `region_append`). Matcher *kinds* (not values, IPs, process names, regexes or rule-set resource paths) are exposed. The projection says `evidence=applied_declaration`; it is **not** an observed packet route, native source-map integrity audit or proof of shadowing. Actual route simulations remain on TUI page 4 and retain unknown outcomes.

DNS is shown by role, transport, port, upstream value **kind** (IP literal versus bootstrap-dependent hostname), bootstrap reference, group detour target, and four top-level role bindings. Raw server hosts/addresses, credentials, native tags and node bodies are excluded. A group DNS binding is not proof that a query used that resolver or transport; DNS T10 still needs controlled network observation.

If current and applied declaration revisions differ, the response reports only whether normalized **effective** Routing, DNS and RuleSet resource metadata structurally differ. This is a comparison of stored declaration states, not a compiler preview, readiness check or application. No operation changes the core, persistent configuration or rule resources.

The server caps non-FINAL route groups at 128 and DNS profile rows at 64, and always includes FINAL. Total counts and truncation flags are explicit, never silently interpreted as complete. The client caps JSON response bodies at 1 MiB before decoding. TUI pages 7 (Routing) and 8 (DNS) share a manually refreshed, bounded projection, sanitize all displayed labels and mask suspicious credential-like/URL-like identifiers; leave-page and request sequence checks prevent stale data reappearing. No background polling, infinite logs, TUN, elevated privileges or network probes are added.

## Verification

Automated tests exercise verified applied generation identity, staged-versus-applied drift, unavailable applied state, exact CN-28 + region origin/order projection, omission of DNS server and matcher values, group/DNS caps, unsafe IDs, untrusted errors, stale async responses and narrow-terminal clipping. The Unix-socket client rejects oversized response bodies. CI (fmt/vet/unit/race/build) and approved-core integration must be green before calling this slice verified.

## Open work

Add safe, compiler-backed per-revision **draft** change preview and explicit guarded Routing/DNS modification/apply/rollback transactions; do not infer DNS transport from configuration bindings. Finish offline CN rule resources and licenses, M2/M3 compatibility, T10/T23 and 72h/7d/30d stability evidence before release.
