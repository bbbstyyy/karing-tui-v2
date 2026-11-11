# ADR 0007: Use KaringX/sing-box 1.13.19 as the M1 stable core baseline

- Status: Accepted
- Date: 2026-10-05

## Context

The project initially selected `KaringX/sing-box@9f020fce...` from `karing_v1.14.0` because it matches the newer Karing source line. A core candidate for this project must be reproducibly buildable before the daemon is allowed to supervise it.

Four provenance runs showed that the inspected 1.14 commit is not a closed standalone source snapshot. The active local replacements point at a workspace that cannot be reconstructed from the older pseudo-version comments, while branch-synchronized sibling snapshots still leave the core tree with incompatible Clash API, DNS, QUIC, and WireGuard APIs. The KaringX repository exposes no successful Actions result for that branch that demonstrates a valid build recipe.

By contrast, the maintained `karing_v1.13.19` branch head `beddeababcc71dfb0c78124598b13341c06c69fb` uses fixed remote KaringX pseudo-version replacements in `go.mod` and retains the Karing extension APIs observed to be internally consistent.

## Decision

M1 uses `karing_v1.13.19@beddeaba...` as the stable standalone Linux core baseline.

This is a stability decision, not a permanent downgrade of project goals. `karing_v1.14.0` remains an explicit upgrade target and may replace the baseline only after a future source/dependency snapshot passes the same provenance and runtime gates.

The M1 reference build:

1. uses the candidate's upstream-pinned Go 1.25.12;
2. builds with `CGO_ENABLED=0` for Linux amd64 and arm64;
3. uses the candidate's `release/DEFAULT_BUILD_TAGS_OTHERS` and `release/LDFLAGS`;
4. appends `with_karing` and `with_shadowsocksr`, which are required by the fork's guarded packages;
5. injects a fixed version through `constant.Version` instead of invoking the Makefile's `@latest` helper;
6. publishes no artifact from the provenance workflow.

## Compatibility consequence

The management plane must target contracts verified against this baseline. Any API or config behavior previously inspected only on 1.14 must be rechecked before it is used as a hard runtime assumption.

In particular, the daemon will continue to verify local listeners and actual proxy behavior rather than relying on a control API response as proof of activation.

## Upgrade rule

A future 1.14+ baseline must satisfy all of the following before replacement:

- exact source and dependency revisions are reproducibly fetchable;
- amd64 and arm64 builds succeed from the lock file without source patches;
- binary SHA-256 values are recorded;
- ordinary-user `version` and config validation work;
- authenticated loopback control API behavior is verified;
- the three expected Mixed inbounds bind only the configured loopback ports;
- no TUN/system-proxy/route-takeover behavior is required;
- rollback and local behavior verification pass through the daemon's apply coordinator.

Until then, long-term stability takes precedence over a nominally newer core version.
