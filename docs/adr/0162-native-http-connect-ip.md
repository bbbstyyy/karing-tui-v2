# ADR 0162 — numeric localhost HTTP CONNECT on the three mixed inbounds (T22 partial)

- **Status:** bounded real native Core protocol preflight only, not complete T22.
- **Depends on:** ADR 0149–0161 and the already approved same-PID Core generation after explicit stop/restart and bounded SOCKS5 reconnect workload.
- **Sandbox:** the same fourth `docker --network none --cap-drop ALL --user 10001:10001 --read-only` container on native amd64 and arm64, with numeric localhost echo target and synthetic localhost Selected SOCKS node. No additional Core, Daemon, net permissions, TUN, external endpoints, credentials or CN resources.

## Motivation

Prior native smoke tested the three mixed ports using SOCKS5 CONNECT with an IPv4 target, but did not exercise the HTTP CONNECT parsing path of the *same real inbounds*. T22 explicitly includes both HTTP and SOCKS. A local numeric-only HTTP CONNECT probe can reveal protocol-specific bypass while retaining the existing airgap envelope.

## Decision

1. In the existing sixth Daemon session after the successful approved-Core restart, Selected failure/restore and 24×3 SOCKS5 reconnects, issue exactly **three real HTTP/1.1 CONNECT** requests to **`127.0.0.1:<ephemeral-loopback-echo-port>`**, once each through the unchanged Rule 2080, Direct 2081 and Selected 2082 mixed inbounds. Include an exact numeric Host header; no external host, DNS, URL, Proxy-Authorization or credentials.
2. Read at most **1,024 bytes** of HTTP response header in bounded one-byte reads so TCP framing cannot consume echo data; demand a complete CRLF-CRLF terminator and HTTP/1.0 or HTTP/1.1 status **200** before forwarding a bounded binary payload. Demand the identical synthetic echo reply. Reject partial headers, non-200 status, malformed status line, oversized headers, wrong echo and invalid types/ports. Close every client socket on any error.
3. Require the *actual* approved Core PID, revision 2 and Applied=LKG generation 2 both before and after the three requests. Only the Selected request may increment the synthetic SOCKS node's successful CONNECT counter (**exactly one**); Rule/Direct must not traverse Selected, and no new Selected refusal or node failure is allowed. The final native synthetic count increases from **51 to 52**.
4. Preserve the existing `finally` explicit Core stop and seventh cold Daemon stopped audit. Add Python mock regressions for correctly bounded numeric requests and echo, malformed/denied HTTP responses, invalid inputs, Selected route crossing/bypass, new refusal, wrong PID and unexpected Core replacement. Native full success adds `T22_AIRGAP_HTTP_CONNECT_IP=ok` and explicitly prints `T22_HOSTNAME_AND_UDP_VERIFIED=false`.

## Hard boundaries

This is only IPv4 numeric loopback HTTP CONNECT through mixed inbounds. It does **not** prove HTTP absolute-form proxying, SOCKS DOMAIN requests, hostname DNS, UDP ASSOCIATE, auth, real remote proxy/DNS, CN 28-group/five-layer SRS, licensed offline tar distribution, T15/T23 power-loss/restore, T20 1,000 reconnects or T25 long soak. T22 overall, T15/T23/T24/T25, Restore/GC and release gates remain OPEN. No TUN or subscription/ISP routing layer, stable `main` unchanged.
