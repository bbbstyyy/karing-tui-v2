# ADR 0145 — Bounded no-follow Linux CN offline resource provenance audit (T24 preflight)

- **Status:** M0/M5 T24 **preflight only**; offline production bundle **blocked**.
- **Depends on:** ADR 0043 pinned Karing 28-group CN snapshot / 68 logical references / 67 existing SRS assets / one absent `geoip:bing`.
- **No scope changes:** Linux ordinary user, no TUN, Custom → GeoSite → GeoIP → ACL → FINAL, CN 28 groups plus separate region append; no subscription/ISP diversion rules.

## Gap

The existing `cmd/cn-resource-audit` computed streaming SHA-256 and byte counts from an operator-selected `--asset-root`, but opened paths through ordinary `os.Open`, which follows symlinks. It did not bound file or aggregate bytes and checked the original file size only at the end. A hostile or accidentally modified asset tree could therefore redirect the audit outside the checkout, hardlink to mutable external files, or cause unbounded CPU/disk reads. Hashing arbitrary bytes does not attest that they came from the immutable pinned Git commit.

## Decision

1. Audit **only on Linux**, with existing pinned asset checkout used as a root opened by `O_DIRECTORY | O_NOFOLLOW`. For each `geosite/`, `geoip/` or `acl/` two-component relative `.srs` path, open the family directory with `openat(O_DIRECTORY|O_NOFOLLOW)` and the file with `openat(O_RDONLY|O_NOFOLLOW|O_NONBLOCK)`. Reject traversal, parent/final symlinks, FIFOs, directories, devices, zero-byte assets and files with hardlink count other than one.
2. Use descriptor-relative `fstatat(AT_SYMLINK_NOFOLLOW)` to compare the named directory/file to the opened descriptors, before and after streamed SHA-256. Compare dev/inode, mode, hardlink count, byte size and mtime/ctime; refuse replacement or changes during the read. This **reduces** path redirection/TOCTOU exposure, but it cannot prove an adversary with write access did not modify bytes earlier or inside an indistinguishable file-system event.
3. Limit input to **8 MiB per file** and **64 MiB total** for the 67 file-backed referenced assets. The pinned source's publicly inspected assets are far smaller; these are *audit-only* conservative budgets, not product update or runtime resource limits. Bound reads even if a file grows while being hashed.
4. Keep `distribution_ready=false` and `license_status=blocked_unresolved_upstream_data_licenses`; preserve exactly **68 references, 67 files and one upstream-absent `geoip:bing`**. No fabricated substitute, no silent DIRECT fallback, no downloaded assets embedded in this repository and no new license claims.
5. Make the dedicated `cn-resource-audit` workflow run for relevant **pull requests** as well as pushes/manual invocations; verify the separate Karing checkout's exact commit `9d28b22fbbcca5818d147629aae151d49d4dcb7b` and clean `assets/datas` working tree before/after reading. Run the bounded audit unit tests and assert output still says distribution blocked, with exact cardinality and total-byte bounds. Only publish a short-retention **provenance-only** JSON artifact.
6. Linux adversarial unit fixtures create a complete simulated closure and reject symlinked files/directories/asset roots, hardlinks, special FIFO, zero-size assets, oversize files, malformed relative paths and aggregate budget exhaustion. General CI also covers the Go unit tests. An isolated audit working tree is **not a license review or release artifact**.

## Release gate and residual risks

To pass T24, future work still needs the legally reviewed per-source license/attribution and redistribution permissions, treatment of the known absent `geoip:bing`, a reproducible exact-byte CN resource manifest/package, both Linux amd64/arm64 offline startup tests with the approved Core, and documented update/rollback behavior. The clean Git checkout plus SHA is **local provenance evidence only**, not a cryptographic signature, supply-chain attestation or proof of actual offline operation. Nothing here changes production Core, Daemon, TUI or SQLite v18, starts the proxy, makes network requests at startup, or authorizes release, restoration or deletion. T15/T23/T24/T25, CN licensing and 72h/7d/30d soak remain **OPEN**; stable `main` and outer Draft PR #1 stay untouched.
