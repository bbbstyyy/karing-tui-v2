# ADR 0228: strict VLESS TCP with verified TLS share-URI import

Status: **MVP-1D implementation candidate**, not full MV-02 acceptance.

## Motivation

The existing `uri-list` and `uri-list-base64` source refresh paths
support Shadowsocks SIP002 and strict Trojan TCP/TLS URIs. The native
sing-box/basic-node parser, declaration compiler and pinned Core have a VLESS
basic subset, but ordinary VLESS share URIs have no conversion path. Rejecting
all VLESS URIs stops popular sources before they can use the guarded snapshot
to first-run declaration and checked Apply workflow.

## Admitted grammar

Only `vless://UUID@host:port?security=tls&encryption=none` is admitted.
Optional `type=tcp`, `sni=HOST`, `allowInsecure=0/false` are accepted.
Missing `security=tls` or `encryption=none`, plaintext, Reality,
WebSocket, gRPC, flow/vision, fingerprint, TLS custom trust, ALPN, transport
headers, UDP packet encoding, an unknown/repeated query key, malformed escape,
non-UUID userinfo, URI path or bad port are **blocking diagnostics**.
No default non-TLS mode, direct route, or silently dropped unsupported
property is allowed.

A UUID token of 32 hex digits or canonical hyphenated 36 digits is normalized
to lowercase canonical hyphenated form. Stable source identity hashes the
exact canonical typed basic outbound including server, port, UUID, explicit
TCP network, `encryption=none` and enabled TLS/SNI. A display fragment,
query order or redundant safe default does not change stable NodeID.
Credentials, full URIs and untrusted query values cannot enter diagnostics
or API error messages.

The converted payload runs through the existing
`singbox.AnalyzeBasicProfile` and domain validator, then the exact same
source snapshot/overlay/first-run/checked Apply gates. A partially invalid
mixed URI list is **not** committed; bad refresh keeps previous accepted
snapshot and does not change Applied or Last-Known-Good generations.

## Evidence and limitations

Unit tests cover supported fields, canonical UUID/query/fragment identity,
duplicate node refusal, Base64 subscription envelope, missing/incompatible
TLS attributes, unsupported fields, malformed/duplicate query keys and
credential-safe errors. A Linux Daemon API test serves a synthetic URI
subscription over loopback, accepts its initial snapshot and rejects an
unsafe subsequent update while retaining the accepted snapshot and Core
generation. The HTTP fixture does not prove VLESS upstream TLS handshake.

Still required for MV-02: actual pinned-Core VLESS TLS and authentication
traffic through Rule/Selected, plus Shadowsocks/Trojan real upstream protocols,
Clash/YAML broad provider compatibility and full user CN routing. This PR
does not touch TUN or reintroduce subscription/ISP routing. CN 28 groups,
five-layer policy, authorized offline rule closure, real restore and 72-hour
soak remain MVP blockers.

Gate: do not merge until the **final PR head** passes Go fmt/Vet/build/tests,
Race 4/4, real Managed Core Integration and Linux amd64/arm64 provenance.
`main` stays unchanged.
