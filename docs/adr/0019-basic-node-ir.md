# ADR 0019: Start node materialization with a strict basic SOCKS/HTTP IR

- Status: Accepted
- Date: 2026-10-05

## Context

Routing and selection now resolve to stable Specific Node tags, but a runnable native configuration still needs concrete protocol outbounds.

Subscription formats contain many protocol and transport fields. Passing those input objects through to sing-box would violate the project boundary that unknown/unvalidated source fields never enter runtime configuration.

The approved 1.13.19 core has clear SOCKS and HTTP outbound schemas. Its HTTP outbound is TCP-only. Its SOCKS implementation supports versions 4, 4a, and 5, with SOCKS4 doing local destination-domain resolution.

## Decision

The first node IR is intentionally narrow and typed:

- plain SOCKS4;
- plain SOCKS4a;
- plain SOCKS5;
- plain HTTP CONNECT.

Each node has stable `ProfileID + NodeID`, a bare server host, non-zero server port, and exactly one protocol option block.

No display name participates in runtime identity or tag generation.

## Network restrictions

- SOCKS4 and SOCKS4a are restricted to TCP in the basic model.
- SOCKS5 may explicitly allow TCP, UDP, or both.
- HTTP CONNECT is TCP-only by the approved core implementation.

These restrictions are compiler/product semantics, not claims that no future protocol extension can support other transports.

## Authentication

Credentials are bounded, valid UTF-8, and reject control characters.

A password without a username is rejected for both SOCKS5 and HTTP. SOCKS4/4a password authentication is rejected.

Secrets remain values inside the immutable generated config; they are never used to derive stable IDs or runtime tags.

## Server validation

The server field is a bare IP literal or conservative ASCII DNS name. It is not a URL and cannot contain userinfo, path/query fragments, or an embedded port.

Unspecified IP addresses are rejected as proxy servers.

IDNA/unicode-domain normalization is not guessed in this initial IR; importers must normalize supported source forms before constructing the node model.

## Compiler closure

`CompileBasicNodeOutbounds` consumes only the Specific Node dependency closure produced by routing/selection.

It:

1. validates every configured basic node;
2. rejects duplicate stable node identities;
3. verifies each configured node has a stable tag in `TargetCatalog`;
4. emits only first-use ordered required nodes;
5. rejects missing nodes or non-node dependencies;
6. emits a field whitelist for the approved core.

Extra configured nodes do not become runtime outbounds merely because they exist.

## Explicitly not supported by this stage

The basic model does not pass through:

- TLS;
- HTTP custom path/headers;
- dialer/detour settings;
- UDP-over-TCP;
- mux;
- custom resolver/dial strategy;
- Shadowsocks, VMess, VLESS, Trojan, Hysteria/Hysteria2, TUIC, or other protocols.

Importers encountering those fields/protocols must report them as unsupported for this compiler stage. They must not silently drop them and claim the node is equivalent.

Later ADRs may add typed protocol/transport blocks one by one, backed by approved-core fixtures.
