# T24 native airgap preflight — ADR 0146/0147

**CI-only, disposable Linux native amd64/arm64, never a production installation guide.**

Use `.github/workflows/core-provenance.yml` to build and SHA-verify the approved Core, compile the management CLI and fetch the **digest-pinned** Python OCI image **on the connected CI runner**. The isolated container has no network (`--network none`), no Linux capabilities (`--cap-drop ALL`), no privilege escalation, ordinary UID 10001, read-only root+staged binaries and a private tmpfs for state. Never mount user settings, share host networking, enable TUN or grant root.

Two **distinct** container executions are required on **both** native architectures: `t24_airgap_bootstrap.py` opens real Daemon/SQLite and private Unix sockets twice, refusing unexpected Core activation and license-capability escalation; `t24_airgap_loopback_core.py` runs the approved standalone Core with a fixed local-only config, checks Clash API denial/identity and sends real SOCKS5 CONNECT messages through rule/direct/selected to a disposable TCP echo service bound solely to **127.0.0.1 inside the same namespace**, then requires clean SIGTERM. CI must print `T24_AIRGAP_NATIVE_BOOTSTRAP=ok` and `T24_AIRGAP_LOCAL_CORE_SOCKS5=ok` in both native jobs. Failures mean a manual hold, not a fallback to connected tests.

This is no claim that a package installs without internet, that CN rules/files are licensed, that DNS/remote nodes or the full five-layer routing policy work, or that Core is controlled by a production Daemon. The 67 unlicensed candidate CN assets, absent geoip:bing, full T24, T15/T23/T25, HMAC/credentials/rollback and long soak remain blocked.
