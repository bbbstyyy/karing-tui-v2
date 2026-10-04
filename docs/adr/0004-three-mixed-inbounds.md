# ADR 0004: Model Rule, Direct, and Selected as fixed loopback Mixed inbounds

- Status: Accepted
- Date: 2026-10-04

## Context

The project requires three explicit proxy entry semantics rather than one ambiguous proxy port:

- Rule: normal traffic subject to mode and the complete routing pipeline;
- Direct: an explicit bypass of business routing to DIRECT;
- Selected: an explicit bypass of business routing to CurrentSelected.

Port conflicts must fail visibly. A process listening on a configured port is also not sufficient evidence that the expected sing-box Mixed inbound is actually present.

## Decision

The domain model contains one `InboundSet` with a loopback listen address and three distinct non-zero ports. The initial defaults follow the project plan:

- Rule: `127.0.0.1:2080`;
- Direct: `127.0.0.1:2081`;
- Selected: `127.0.0.1:2082`.

These are project defaults, not claims about Karing's original defaults. The model never searches for or substitutes a free port. A collision therefore remains a configuration/startup error instead of silently moving clients onto a different listener.

LAN wildcard or non-loopback addresses are rejected. Explicit IPv6 loopback can be represented as a separate configuration choice, but the default stays IPv4 loopback.

## Local protocol readiness

`internal/coreapi.MixedInboundProbe` connects to all three configured listeners and performs only the SOCKS5 no-auth method negotiation (`05 01 00` -> `05 00`). This is sufficient to prove that the exact expected port is speaking the SOCKS side of a Mixed inbound without requiring Internet access or opening a destination connection.

The authenticated Clash `/version` probe and the three Mixed listener probes can be combined as `LocalHealthProbe`. External node reachability is deliberately excluded from this readiness decision.

## Current integration boundary

The model and local protocol probe are implemented, but `proxy_inbounds` remains false. The project still needs deterministic sing-box config generation that binds the three inbound tags to the correct Rule/DIRECT/CurrentSelected routing semantics, followed by real-core integration tests.

The health probe also does not by itself prove that Direct or Selected chose the right outbound. That belongs to later controlled proxy-behavior tests and T13/T22 coverage.
