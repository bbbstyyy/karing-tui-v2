# ADR 0147 — Native no-network Core loopback data-plane preflight

**Status:** T24 partial preflight, NOT full offline CN release. Depends on ADR 0145 (CN resource source-only audit) and ADR 0146 (nonroot amd64/arm64 network-none management Daemon bootstrap). Linux ordinary user, no TUN/route takeover/system proxy; original CN 28 preset groups, five-layer routing and absence of subscription/ISP layers unchanged.

## Gap and decision

ADR 0146 ran actual Daemon+SQLite/Unix socket in a disconnected network namespace but performed only Core `version` / `check`. It did not run Core or transmit data. Its test OCI tag was mutable.

- Preserve the original native amd64/arm64 approved Core SHA and management-bootstrap tests. Pin the test Python multi-platform OCI image to **docker.io/library/python@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70**, independently observed in both green ADR 0146 runs. The **CI host still has network during staging/build**; this only pins the test container image, not the entire supply chain.
- In an **independent** `docker run --pull never --network none --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 --read-only` container, using private tmpfs and readonly pre-staged approved Core, enforce native arch, nonroot, no effective capabilities and no route to TEST-NET.
- Generate only the inert local Core config: three mixed listeners on 127.0.0.1:28080/28081/28082 (rule/direct/selected), direct/block/selected outbounds, and localhost Clash API with disposable token. Fail on public listener, external URL/DNS/SRS, TUN, system proxy or unexpected config sections. Run Core version/check and **real run**; require 401 on unauthenticated Clash API, approved version on authenticated API, and full SOCKS5 TCP CONNECT + payload round trip from **each** listener to a local ephemeral 127.0.0.1 TCP echo server. Bound all reads and timeouts and require clean SIGTERM exit.
- Standard CI Python regression tests reject invalid SOCKS handshake/target, API auth bypass, remote endpoints, changed inbounds, unauthorized output or external resources. Both native jobs must pass both the previous Daemon/SQLite bootstrap and the new Core-local data-plane test on the exact same PR SHA.

## Evidence limits

These are **intra-container loopback packets only**. This DOES NOT verify remote proxy traffic, DNS routing, real multi-layer CN policy or `.srs` parsing, legal redistribution, a final airgap-installed package, production Daemon/Core apply, rollback, real VM reboot or power cut. The 68 logical CN refs, 67 candidate files and absent `geoip:bing` remain provenance/license blockers. `core_distribution=false`, `cn_preset_offline_bundle=false`, no restore/GC authorization. T15/T23/T24/T25, approved licenses/attribution and 72h/7d/30d soaks all remain OPEN; stable main and outer Draft PR #1 unchanged.
