# ADR 0230: verified Trojan TCP/TLS real-Core traffic fixture

Status: **MVP-1C integration candidate / Pre-MVP**, not MV-02 or CN acceptance.

## Why

URI-list and Base64 Trojan TCP/TLS parsing has strict field-allowlisting and
snapshot atomicity tests. It still lacks a user-source-to-checked-Core proof
with real Trojan authentication and tunneled traffic. This work adds such
an offline Linux test, without extending accepted transport/TLS modes.

## Evidence path

`TestManagedCoreRealMVPImportedTrojanTLSFlow` uses the pinned Core executable
as an ordinary Linux user. A loopback HTTP subscription serves a real
`trojan://PASSWORD@127.0.0.1:PORT?security=tls&type=tcp&sni=...` URI.
The public Profile API imports and refreshes it; a selected stable NodeID
is bound to an initial declaration through read-only preview, exact SHA
receipts and an explicit acknowledgement of `proxy-only-no-cn`.
The separate guarded Apply preview/confirm performs Core Check, activate,
verify and durable LKG commit.

The local Trojan fixture presents a temporary signed certificate with a
test-only DNS SAN, trusted by the child Core through `SSL_CERT_FILE`;
verification is never disabled. The independent Trojan peer reads the
56-hex SHA224 password proof and CRLF, TCP CONNECT command, IPv4 target,
port and final CRLF. It opens the loopback target only after successful
constant-time authentication and target validation.

From live Core Rule and Selected SOCKS5 inbounds, and HTTP CONNECT Rule
inbound, tests require both an authenticated upstream hit and target echo.
The Direct inbound must reach target *without* a Trojan hit; a wrong
SHA224 password on an otherwise verified TLS connection must fail with
zero target/upstream traffic.

A bad subsequent subscription update (`security=reality&type=grpc`) is
rejected, must not change the accepted snapshot, Applied or LKG, and cannot
reuse a stale initial stage receipt. The active LKG still forwards Trojan
traffic after this bad update and after explicit stop/restart. No remote
network, TUN, system routing, production certificate, secret logging or
subscriber-supplied routing is involved.

## Scope and gates

This verifies a strict Trojan TCP/TLS subset only. It neither validates
public third-party services nor supports Reality, websocket, gRPC, insecure
TLS, pinned certificates, advanced ALPN or UDP transport. It does not
establish full CN 28-group parity, authorized offline rule-set closure,
five-layer CN routing/DNS, Clash/YAML coverage, Shadowsocks real upstream
traffic, real restore or 72h soak. The project remains **Pre-MVP**.

Keep this PR Draft and stacked after #111; merge only after parent PR
passes its final-base CI and is merged. Rebase this PR on the resulting
development SHA, then require on that exact new head Go format, Vet,
unit and integration-compile, build, 4 race shards, managed pinned-Core
traffic and native linux-amd64/arm64 provenance. Stable `main` is unchanged.
