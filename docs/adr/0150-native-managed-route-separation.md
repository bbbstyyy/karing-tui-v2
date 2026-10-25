# ADR 0150 — T24 synthetic three-entry route separation

**Scope:** test-only strengthening of ADR 0149's real Daemon-managed network-none loopback test; does not authorize release, core distribution, CN resources, privileged operation or external network traffic.

Previously successful SOCKS5 echoes on Rule 2080, Direct 2081 and Selected 2082, plus a nonzero count of local selected-node requests, could not prove that the Rule and Direct routes had *not* traversed the Selected node. Each path should be independently accounted for.

**Decision:** introduce a bounded per-cycle probe that requires the synthetic local SOCKS node to receive zero requests from Rule/Direct and exactly one from Selected, on both the initial managed-Core start and the persisted-generation Daemon restart. Check node error state at each hop. Unit regressions reject accidental all-selected routing, selected bypass, and node failure; no production routing logic changes.

**Evidence boundary:** the only tested traffic is synthetic numeric localhost TCP to a controlled echo endpoint with an isolated test-only SOCKS node. Five-layer CN, real DNS/ruleset resources, remote proxies, 72h/7d/30d soak, full distribution, and recovery/backup release gates remain OPEN. No TUN and no subscription/ISP diversion.