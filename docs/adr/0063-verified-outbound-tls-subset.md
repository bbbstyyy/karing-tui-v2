# ADR 0063: Add outbound TLS only as a verified fail-closed subset

## Status

Accepted.

## Context

M3 protocol compatibility requires preserving node security parameters without silently widening support.

The approved KaringX/sing-box core exposes a large outbound TLS object: standard TLS verification controls plus ALPN, versions, cipher suites, certificates, ECH, uTLS, Reality, fragmentation, kTLS and other extensions. Importing a TLS-bearing node while retaining only part of that object would change connection semantics.

The fixed core also distinguishes an omitted TLS object from an explicit object whose `enabled` field is false. Some protocol constructors branch on whether the TLS object exists before the TLS factory evaluates `enabled`, so the project must not normalize an explicit disabled object into an omitted object without proof.

## Decision

The first runtime TLS slice is deliberately narrow.

It is available only on the currently modelled VMess, VLESS and Trojan node types and accepts exactly:

- `enabled: true`;
- optional `server_name`;
- optional `insecure`;
- optional `disable_sni`.

An omitted or JSON-null `tls` field remains absent. An explicit TLS object with `enabled:false` is rejected in this verified subset.

Any other TLS field, including Reality, uTLS, ECH, ALPN, version/cipher/curve controls, certificate material or paths, client certificates, fragmentation, kTLS and TLS tricks, blocks the whole candidate profile update. Multiplex, V2Ray transport and dial extensions remain separate compatibility work.

HTTP, SOCKS and Shadowsocks do not gain TLS merely because the shared TLS model exists; their current importer/compiler boundaries remain unchanged.

## Data path

The accepted subset is preserved end-to-end:

```text
native sing-box outbound
  -> strict profile analysis
  -> immutable source-node payload
  -> materialized domain Node.TLS
  -> declaration-v1 tls object
  -> native compiler tls object
  -> approved fixed core
```

No layer is allowed to infer defaults that were not present in the accepted source.

## Validation

Regression coverage verifies:

- TLS field validation and protocol binding;
- importer acceptance of the verified subset for VMess/VLESS/Trojan;
- rejection of explicit disabled TLS and unmodelled TLS extensions;
- snapshot persistence across SQLite close/reopen;
- declaration round-trip;
- exact native JSON lowering and omission when TLS is absent;
- successful ordinary-user managed-core integration against the approved fixed core.

## Consequences

Common standard TLS nodes can now be represented without pretending that advanced TLS compatibility exists.

Reality, uTLS, ECH and other advanced TLS features remain explicitly unsupported until they have their own field-level model and fixed-core regression evidence.
