# ADR 0229: pinned Core VLESS TCP/TLS authenticated traffic evidence

Status: MVP-1C/1D integration candidate; not full MV-02 or MVP release acceptance.

## Test path

The Linux `integration` test `TestManagedCoreRealMVPImportedVLESSTLSFlow`
uses the locked native Core binary, an ordinary user, four separate loopback
inbound/control ports and no TUN, internet access, system routing or DNS
override. The test creates a temporary local signing certificate with an
explicit DNS SAN. Its PEM is trusted only inside the test process and inherited
by the child Core through `SSL_CERT_FILE`, using normal certificate
verification instead of `insecure=true`.

A local HTTP source serves a strict
`vless://UUID@127.0.0.1:port?security=tls&encryption=none&type=tcp&sni=...`
URI. The user-facing Profile Source API stores and refreshes it; the accepted
stable node is selected with the first-run preview/one-time acknowledged CAS
stage, and the separate checked Apply API compiles, Core Checks, activates,
verifies, and commits the exact declaration. No hand-seeded runtime JSON,
background automatic application or imported subscription rules are involved.

An independent local TLS/VLESS TCP fixture checks SNI, authenticates the
16-byte UUID, parses the destination and TCP command and forwards the tunnel
only after authentication. Real SOCKS5 Rule/Selected and HTTP CONNECT Rule
inbounds must produce both fixture-authentication and loopback echo
observations. Direct inbound must reach echo without an upstream VLESS hit.
A wrong UUID over otherwise trusted TLS must be refused without target traffic.

An unsupported Reality/gRPC source update is rejected by the public API and
must preserve the previously accepted snapshot, applied generation and LKG.
Replaying the old initial stage is 409. The previously applied Core must
continue carrying VLESS traffic after the bad refresh and again after a
controlled stop/restart. Dynamic source errors and API replies may not expose
the imported UUID. This is actual local protocol and Core traffic, not merely
native JSON comparison or a detached parser unit test.

## Scope and release boundary

This is the **verified TCP-over-TLS URI subset**, with no Reality, QUIC,
WebSocket, GRPC, Vision, packet encoding, custom certificate trust transport,
advanced DNS, or unsupported flow. The certificate fixture is ephemeral test
data, not a bundled third-party provider certificate or licensed ruleset.
It does not certify unrelated VLESS server implementations, live public
subscriptions, CN regional DNS routing or all TCP/UDP combinations.

MV-02 additionally requires the full selected provider format matrix and
real Shadowsocks/Trojan upstream authentication, plus user-facing migration
and routing evidence. CN 28 groups, source-licensed offline rule closure,
five-layer CN/DNS behavior, actual recovery and 72-hour endurance remain
MVP blockers. Do not mark the release as MVP Beta based on this test alone.

As a stacked PR on #110 this change must remain Draft until #110 merges and
the independent new head is revalidated. Exit checks: Go fmt/Vet/tests/build,
Race 4/4, real pinned-Core integration and Linux amd64/arm64 provenance.
The stable `main` branch is not modified.
