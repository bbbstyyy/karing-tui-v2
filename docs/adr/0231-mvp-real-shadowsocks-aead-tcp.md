# ADR 0231: real pinned-Core classic Shadowsocks AEAD TCP traffic

Status: **MVP-1C integration candidate / Pre-MVP**. This is not full
Shadowsocks coverage, CN parity, or an MVP Beta release sign-off.

## Why this test exists

The URI-list SIP002 importer already accepts Shadowsocks basic nodes. A
successful parser, stable NodeID and generated outbound JSON do not establish
that the pinned sing-box Core can authenticate, decrypt and forward real
Shadowsocks traffic. This test adds an independent loopback peer implementing
**classic Shadowsocks AEAD aes-256-gcm TCP** as defined in SIP004/SIP007
(Shadowsocks specification: https://shadowsocks.org/doc/aead.html).
It is deliberately **not** Shadowsocks 2022 or a generic production server.

## Independent protocol fixture

The test-only server uses the legacy EVP_BytesToKey MD5 chain to derive the
32-byte password-based key, then HKDF-SHA1 with a unique stream salt and
the info string `ss-subkey`, followed by AES-256-GCM. Each AEAD operation
uses a 12-byte little-endian incrementing nonce. An encrypted TCP chunk is
an authenticated two-byte big-endian length and its authenticated payload;
both operations have independent 16-byte tags and advance the nonce.
Length is bounded to `0x3FFF`. The server authenticates the full length
and first payload and checks IPv4 destination/port before dialing any target.

A response is encrypted as an independent stream with a fresh random salt
and independent nonce sequence. The fixture is checked with negative
cases for incorrect master password, altered salt/length/payload tags,
truncation, wrong destination and oversized chunks. No TLS or insecure
transport option is represented as supported in this subset.

## Real user and Core path

The `integration && linux` test
`TestManagedCoreRealMVPImportedShadowsocksAEADFlow` starts a local synthetic
SIP002 source containing `ss://BASE64URL(aes-256-gcm:PASSWORD)@host:port`,
imports it through public Profile Source/Refresh API, confirms a stable
accepted NodeID, and stages the explicit first-run `proxy-only-no-cn`
declaration by preview SHA/CAS acknowledgement.

A separate checked Apply request runs the pinned Core Check, activation,
health verification and durable generation commit. A live Core sends
SOCKS5 Rule/Selected and HTTP CONNECT Rule traffic through the independently
authenticated Shadowsocks upstream to a loopback echo marker. Direct
inbound must bypass the Shadowsocks peer, and an injected wrong-password
frame must never hit the target.

A subsequent unsupported `transport=grpc` source refresh must fail
atomically, preserve the previously accepted source snapshot and Applied/LKG
generation, reject stale first-run stage replay, and leave live proxy traffic
working through bad refresh and a controlled stop/restart.

All services bind to loopback; process runs as ordinary Linux UID, with
no TUN, external proxy, system route changes, secret logging or imported
subscription/ISP routing. On public API failure paths, test-only credentials
are not echoed. Test evidence is bound to the exact pinned Core SHA.

## Release gates

This test cannot establish Shadowsocks 2022, UDP compatibility, plugin
transports, other ciphers, real third-party providers or 72-hour endurance.
It also does not replace complete Clash/YAML source support, CN 28-group
five-layer routing, licensed offline rule sets and DNS, real backup/restore
or dual-architecture delivery. The project remains Pre-MVP.

Keep Draft until the **final PR head** passes Go fmt/Vet/tests/build,
the integration compile gate, all Race 4 shards, pinned managed-Core real
traffic and linux-amd64/arm64 provenance. It is independent of the ongoing
Trojan test PR and does not change stable `main`.
