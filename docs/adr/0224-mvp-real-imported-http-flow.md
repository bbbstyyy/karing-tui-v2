# ADR 0224: MVP-1C imported HTTP node via pinned Core

Status: integration candidate, not MV-02 or MVP acceptance.

## Evidence boundary

Add `TestManagedCoreRealMVPImportedHTTPFlow` to the existing
`managed-core-integration` workflow (its `-run TestManagedCoreReal`
selector includes this test). The workflow builds/verifies the pinned
Core before executing as an unprivileged Linux user.

The test operates only on loopback: an HTTP sing-box source server emits
one authenticated HTTP proxy node and an intentionally untrusted routing
policy; a private CONNECT proxy forwards only to a local echo listener;
a project-managed Core owns the Rule/Direct/Selected mixed listeners.

It exercises the existing protected HTTP API sequence:
create source -> manual refresh -> node paging -> snapshot-to-declaration
preview and explicit digest stage -> compiler checked-apply preview and
confirmation -> actual Core start -> checked CurrentSelected change ->
SOCKS5 Rule/Selected and HTTP CONNECT Rule tunnels -> Direct control
tunnel -> invalid source refresh -> ongoing old-generation traffic ->
stop/restart -> old-generation traffic. It checks the ignored subscription
route diagnostic and the absence of that rule from persisted native
configuration. Failure verifies unchanged accepted snapshot, live Core
PID, Applied/LKG generation, and refusal of stale stage receipts.

## Deliberate limitations

- Initial V1 routing and selection declaration are built by the guarded
  first-run public API, with explicit proxy-only/no-CN acknowledgement.
  This does not prove the complete user-facing TUI flow or CN readiness.
- The imported **HTTP proxy** is an integration stepping stone, not proof
  of Shadowsocks, VLESS or Trojan transport/TLS compatibility.
- The traffic proof is bounded to synthetic loopback IPv4 CONNECT
  (no real Internet, no production DNS/GeoIP/ACL or licensed CN data).
- This PR does not authorize restoring backups, change any runtime routes
  automatically, or remove the no-TUN and five-layer CN requirements.
- Do not claim MV-02 complete until an ordinary user can complete this
  operation without fixture-seeded runtime JSON, including at least one
  supported widespread subscription format.

## Gate

Merge only when the **final PR head** passes Go fmt/vet/test/build,
all four Race shards, Managed Core Integration with real approved Core,
and Linux amd64/arm64 provenance. Record actual result links rather
than treating a newly added test as a passing test.
