# ADR 0065: URI-list conversion targets the canonical basic-node model

## Status

Accepted.

## Context

M3 requires common subscription-format conversion, but accepting share links is unsafe if their transport, TLS or identity semantics are guessed.

The current runtime already has a strict, fixed-core-tested sing-box basic-node path. A second converter-specific runtime model would duplicate validation and make field-loss regressions harder to detect.

Shadowsocks SIP002 has a compact mapping that fits the existing basic Shadowsocks model: method, password, server, port and optional plugin/plugin options. Other share-link families encode transport and security defaults whose complete mapping is not yet represented.

## Decision

Add a `uri-list` ProfileSource format as decoded UTF-8 text with one URI per non-empty, non-comment line.

The first supported URI subset is hierarchical Shadowsocks SIP002:

```text
ss://BASE64URL(method:password)@host:port[?plugin=...][#display-name]
```

The converter accepts URL-safe base64 with or without padding. It rejects:

- unsupported URI schemes;
- the legacy base64-whole Shadowsocks form;
- unknown or repeated query parameters;
- empty/malformed credentials, host or port;
- duplicate semantic nodes;
- lines over 16 KiB;
- profiles over 10,000 node lines.

The optional `plugin` value is split at the first semicolon into the native sing-box `plugin` and `plugin_opts` fields.

## Stable identity

The URI fragment is display metadata, not identity.

The converter canonicalizes the semantic Shadowsocks fields without a tag, hashes that JSON, and uses the digest-derived `uri-...` value as SourceKey/tag. Changing only `#display-name` therefore produces a rename on the same stable NodeID.

Two URIs with the same semantic canonical payload are a duplicate-source error rather than two separate nodes.

## Runtime reuse

Each accepted URI is converted to a canonical sing-box outbound JSON object and then passed through the existing strict sing-box basic importer.

The durable snapshot stores that canonical JSON payload while the snapshot source hash covers the exact URI-list source bytes. Materialization for `sing-box` and `uri-list` snapshots uses the same canonical sing-box node decoder.

Unsupported URI entries produce blocking diagnostics. A mixed supported/unsupported list never advances the accepted snapshot.

## Validation

Tests cover:

- SIP002 method/password/server/port conversion;
- IPv6 authority parsing;
- plugin/plugin-options mapping;
- fragment rename preserving SourceKey and NodeID;
- unknown query and unsupported scheme refusal;
- duplicate semantic node refusal;
- oversized line refusal;
- refresh persistence and source-kind provenance;
- failed partial refresh preserving the previously accepted snapshot.

## Consequences

M3 now has a local deterministic format-conversion path without any dependency on third-party conversion services.

VMess, VLESS, Trojan and other share URI schemes, legacy Shadowsocks forms, base64-wrapped V2Ray subscriptions and Clash/YAML remain explicit future compatibility work and must fail closed until mapped field-by-field.
