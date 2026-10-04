# ADR 0009: Build a project-owned standalone entrypoint over the locked Karing core library

- Status: Accepted
- Date: 2026-10-05

## Context

The KaringX/sing-box 1.13.19 source has two incompatible CLI build surfaces for this project.

Without `with_karing`, the fork does not compile because shared packages such as `common/debug`, `common/fix`, `common/statistics`, and `common/gofree` have no buildable files even though the core imports them.

With `with_karing`, the upstream `cmd/sing-box` command is replaced by Karing's app-service CLI. That CLI requires a service-config path and, on Linux, calls `makeProcessSingleton()`, which enumerates processes and terminates or kills another process when its executable basename matches. That violates the project's ownership boundary and T19.

The issue is therefore the upstream CLI package, not the locked Karing library itself.

## Decision

The M1 core is built from the unchanged locked KaringX/sing-box library source with the required `with_karing,with_shadowsocksr` tags, but **does not build upstream `cmd/sing-box`**.

Instead, the project owns a minimal entrypoint template at `resources/core-entry/main.go.txt`. During the reproducible core build it is copied into the locked source tree as `cmd/karing-tui-core/main.go` and compiled inside that module, so the candidate's pinned KaringX replacements remain authoritative.

The entrypoint intentionally exposes only:

- `version` / `version -n`;
- `check -c <config>`;
- `run -c <config>`.

It uses the candidate's own option decoder, registry context, `box.New`, `Start`, and `Close`. It does not implement Karing app service setup, same-basename singleton enforcement, SIGHUP hot reload, TUN setup, or any privilege escalation.

## Why this is not a core fork

No upstream library source file is modified. The project replaces only the executable entrypoint, which is already an architectural responsibility of the daemon-managed product.

The wrapper is versioned in this repository, included in the provenance workflow trigger set, and built against one exact locked Karing source commit and exact module replacements.

## Lifecycle consequence

Configuration application remains process-replacement based. The wrapper deliberately omits SIGHUP reload because the fixed Clash `PUT /configs` path is not a verified full reload contract. The daemon's apply coordinator owns check, activation, local verification, commit, and rollback.

The wrapper handles SIGINT/SIGTERM and closes the box cleanly. The daemon supervisor still owns the child process group and bounded restart policy.

## Approval gate

This decision is accepted only if provenance proves:

- Linux amd64 and arm64 compile from the lock;
- the native amd64 wrapper reports the injected version as an ordinary user;
- `check` accepts the restricted three-inbound smoke config;
- `run` binds the exact configured loopback ports;
- unauthenticated Clash API access is rejected and Bearer-authenticated `/version` matches the locked contract;
- all three Mixed listeners answer a SOCKS5 greeting;
- shutdown by SIGTERM exits cleanly.

Until those checks pass, `build_approved` remains false.


## Provenance run #8 result

Run #8 passed the project-owned entrypoint build on both architectures.

Recorded candidate hashes:

- linux/amd64: `829452e2927ab8a9836fec398d5bbade259b3837df774c53afb3ec4eb20a1569`
- linux/arm64: `77a46000241540067c903bbfdf7c320638066abb9888635bc7a3f1810ee4b512`

The amd64 job also passed the full ordinary-user runtime smoke: injected version, configuration check, process start, unauthenticated Clash API rejection, Bearer-authenticated `/version`, all three Mixed SOCKS5 greetings, and clean SIGTERM shutdown.

The next provenance gate runs each architecture on a native hosted runner and requires the rebuilt binary to match the recorded SHA-256 before executing the same smoke. This closes the plan's "each architecture basic executability" requirement rather than treating an arm64 cross-build alone as execution evidence.
