# ADR 0232: strict Clash YAML source to authenticated native Core

Status: MVP-1D / MV-02 implementation candidate, **Pre-MVP**.

## Decision

Add the ordinary source format `clash-yaml` instead of treating YAML as
an unchecked JSON-like document or guessing which unsupported attributes
are safe. Pin the actively maintained YAML organization v3 module and
its checksum. Parse a single bounded YAML AST: maximum 2 MiB, 4,096 proxies,
160,000 syntax nodes, depth 48 and scalar length 16 KiB. Reject duplicate
mapping keys (including in subscription policy), aliases, anchors, explicit
tags, unsupported schema tags and multi-document payloads.

A minimal practical proxy subset is admitted:
- Shadowsocks `ss` with classic `aes-256-gcm` password and TCP only.
- Trojan with a password, TCP and independently verified TLS; SNI optional.
- VLESS with an explicit TLS true, UUID, encryption none and TCP only.

All `skip-cert-verify: true`, `udp: true`, unsupported transports/flows,
advanced TLS, SS plugins, unknown per-proxy keys, invalid target/port,
duplicate display names and semantic duplicate proxies cause a blocking
diagnostic. No "best effort" partial accepted snapshot. Root `tun`,
`proxy-providers`, `rule-providers` and unknown top-level keys are blocked.

Source `rules`, `proxy-groups` and `dns` are deliberately **ignored with
explicit diagnostics** and are never mapped to project five-layer CN policy.
Selected conventional runtime/inbound properties (ports, mode, allow-lan,
external-controller, etc.) are explicitly reported as ignored, not executed.
A change in subscription rules cannot rewrite native Rule/Direct/Selected
policy, DNS or request elevated OS network privileges.

Materialize each admitted proxy as an equivalent canonical basic sing-box
node and run it through the *existing* typed importer/domain validator.
Compute stable `clash-<sha256>` from semantic JSON excluding display name,
then bind the tag and immutable canonical payload to the accepted snapshot.
Changes in name, YAML field order or explicit `udp: false` must not move the
source identity. Never print YAML parse errors because they can contain
credentials; blocking diagnostics describe code and array index only.

## Evidence and release boundaries

Unit evidence covers supported SS/Trojan/VLESS, field fidelity, ignored
subscription policy, duplicate names/identity, YAML bombs/aliases/tags,
malformed escapes, unknown fields, rejected insecure TLS/UDP and credentials
not appearing in diagnostics. A loopback Profile API test verifies valid
source refresh and atomic rejection of a partly invalid later update:
the existing snapshot and untouched applied generation/LKG survive.

A real pinned-Core local Trojan TLS integration test additionally uses an
HTTP-served Clash YAML subscription to exercise accepted source → selected
NodeID → guarded initial declaration preview/stage → separate checked
Apply → SOCKS5 Rule/Selected, HTTP CONNECT Rule, Direct bypass, TLS password
authentication and local echo → invalid source refresh preserving LKG and
controlled restart. That test verifies a strict supported subset only,
not arbitrary Clash provider YAML.

This does not close the CN 28-group licensed offline rule closure or
geoip:bing gap, five-layer CN and DNS real traffic, TUI complete operator
flow, authentic backup restoration or 72-hour soak. Main remains unchanged.
No TUN or subscription/ISP routing is enabled.

Merge only after **this exact PR head SHA** passes Go fmt/Vet/build/tests,
integration compile, Race 4/4, pinned real Managed Core Integration and both
Linux amd64/arm64 Core Provenance. Any rebase requires fresh CI results.
