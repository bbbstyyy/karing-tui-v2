# ADR 0151 — T24 managed Selected-node SOCKS refusal and local failure isolation

- **Status:** synthetic native amd64/arm64 `--network none` fail-closed integration preflight; **not** a product or release acceptance.
- **Depends on:** ADR 0149 committed-generation managed Core loopback, ADR 0150 per-entry route separation.
- **Unchanged:** Linux ordinary UID; no TUN, system proxy, system DNS, privileged networking, remote resources, subscription/ISP routing layer, or redistribution approval.

## Risk closed within the synthetic experiment

Before this change a healthy synthetic Selected outbound was tested, but the managed system had not been required to refuse that route once the selected peer explicitly rejected its SOCKS5 CONNECT. A broken selector could return a success or silently switch to the DIRECT outbound, and a shared failure could impair otherwise healthy Rule/Direct proxy listeners.

## Decision

Inside the existing **fourth** native, nonroot, capability-free, network-none container:

1. Preserve the real V1 Unix-socket declaration commit/compile/apply, approved Core child, persisted generation and bounded 127.0.0.1 TCP echo target. Do not change the generation or introduce external endpoints.
2. Extend the **synthetic selected SOCKS5 node only** with a switch to return an explicit `0x05` SOCKS5 CONNECT denial, without dialing the echo server. Count denials separately from successful relay requests.
3. After an ordinary successful three-inbound probe, enable this failure for a single bounded Selected connection. While refusal is active, Rule (2080) and Direct (2081) must still complete distinct echo payloads without contacting the Selected node. Selected (2082) must return a non-success SOCKS5 result or close without success, within the socket timeout; a successful CONNECT, malformed response, or timeout rejects the entire probe.
4. Require an actual request to reach the denying synthetic node, no corresponding successful relay, and a still-running **same-PID**, same-committed-generation managed Core with no recovery requirement. Disable refusal in `finally`; Selected must then perform a fresh successful relay, while Rule/Direct remain independent.
5. Repeat the success → explicit refusal → recovery cycle after stopping Core, restarting Daemon on the **same throwaway SQLite state**, and explicitly starting the same generation again. Require exactly four successful selected relay requests across both cycles, at least two denials, durable stop and no leftover default listeners.
6. Add fast stdlib regressions for valid/invalid SOCKS5 refusal responses, bogus ports, no synthetic outbound dial under intentional refusal, cross-routing of Rule/Direct, Selected bypass, node errors, and rollback of the test-only fault switch. The preexisting four native CI containers and pinned approved Core SHA remain mandatory.

## Limits

This validates **application-level SOCKS5 CONNECT rejection by a controlled localhost-only synthetic upstream**, not a physical link outage, external proxy availability, congestion, retries under real network loss, DNS failure or live CN rules. It exercises no backup/restore, actual VM reboot, electrical power cut, offline installation tar or long soak. Continue to report `T24_CN_RULESETS_OR_REMOTE_DNS_VERIFIED=false` and `T24_OFFLINE_DISTRIBUTION_OR_RESTORE_APPROVED=false`. CN source licenses and the missing `geoip:bing` remain blocked, as do T15/T23/T24/T25 and 72h/7d/30d soak; keep `core_distribution=false`, `cn_preset_offline_bundle=false`, stable `main` unchanged and outer PR #1 Draft.
