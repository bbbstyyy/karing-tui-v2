# ADR 0056: Basic sing-box imports are analyzed before snapshot commit

## Status

Accepted.

## Context

M3 starts with native sing-box because it provides explicit outbound tags and a structured JSON source. The project still cannot treat an arbitrary sing-box configuration as a runtime configuration: subscription routing is intentionally excluded, transparent/privileged inbounds are forbidden, and the current node compiler only materializes a narrow HTTP/SOCKS subset.

A partial importer that keeps only `type/server/port` while silently discarding TLS, detour, UDP-over-TCP or protocol-specific fields would violate the plan. Likewise, committing a partially parsed source before compatibility analysis completes would make a failed update replace a usable snapshot.

## Decision

`internal/importer/singbox.AnalyzeBasicProfile` is a pure analysis stage.

It:

1. validates the source through the existing proxy-only safety gate before extracting nodes;
2. hashes the exact source bytes;
3. reports source `route` and `dns` policy as ignored by product policy rather than importing it;
4. reports runtime context such as inbounds/experimental sections separately from profile node state;
5. treats `direct`, `block` and `dns` outbounds as non-node runtime plumbing;
6. accepts only the node fields already represented by the current domain/compiler:
   - plain HTTP CONNECT: tag, server, server_port, username, password;
   - SOCKS 4/4a/5: tag, server, server_port, version, username, password, network;
7. rejects automatic commit when a proxy protocol is unsupported or when a supported protocol contains any unmodelled field;
8. retains the complete accepted outbound object as the node payload for durable snapshot storage.

SOCKS follows the pinned/core-compatible defaults already used by the domain model: omitted version means SOCKS5 and omitted network means both. The domain validator remains authoritative for protocol constraints such as SOCKS4/4a TCP-only and password restrictions.

Analysis diagnostics have explicit levels. Any error-level compatibility diagnostic blocks the profile transaction; informational policy diagnostics do not.

## Snapshot transaction

`internal/profileupdate.CommitBasicSingBoxProfile` connects analysis to ADR 0055:

```text
source bytes
  -> safety check
  -> compatibility analysis
  -> no blocking diagnostics
  -> one immutable profile snapshot transaction
  -> materialize domain nodes using reconciled stable NodeIDs
```

Unsupported or malformed updates never advance the current profile snapshot.

The snapshot stores each accepted outbound payload and a per-node SHA-256. Reads verify the payload digest before returning it. Payloads are bounded to 1 MiB per node and 64 MiB total per accepted profile snapshot.

The coordinator can reconstruct basic domain nodes from the persisted payload after daemon restart, without re-fetching the source.

## Routing boundary

A native source's `route` content does not create RuleGroups, FINAL, rule-provider bindings or a subscription routing layer. This is an intentional product-policy diagnostic, not an importer parse failure.

Source selector/urltest outbounds are not silently converted into project SelectionGroups. Until an explicit compatibility mapping is designed, they block a complete node import rather than being discarded.

## Compiler determinism

This slice does not make the compiler read the mutable current profile snapshot. The plan requires compiler input to come from an explicit revision. A later declaration-schema decision must bind exact profile snapshot IDs/revisions into a declaration before imported nodes can participate in deterministic runtime compilation.

## Validation

Tests cover:

- supported HTTP/SOCKS extraction and defaults;
- routing/DNS policy diagnostics;
- privileged/TUN source rejection;
- unsupported protocol and unsupported-field refusal;
- duplicate source-tag refusal;
- stable NodeID preservation when node payload changes;
- persistence/reload of the exact accepted payload;
- failed import isolation;
- explicit confirmation for a genuinely empty accepted profile.

## Consequences

Native sing-box now has a safe first import path for the currently supported node subset without weakening the no-subscription-routing rule.

VLESS, VMess, Trojan, Shadowsocks, Hysteria/Hysteria2, TUIC, TLS/Reality, transport, Mux, detour and provider-backed node materialization remain explicit compatibility work. They must be added field-by-field with importer diagnostics and compiler coverage before being considered supported.
