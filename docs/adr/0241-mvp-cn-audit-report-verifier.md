# ADR 0241: strict, bounded CN source audit-report verification

Status: MVP-2 / MV-07 partial; license and distribution remain **blocked**.

The new `cn-resource-audit --verify-report FILE` command validates a bounded
(128 KiB) report independently of the asset auditor. It checks source and
asset provenance, all 68 logical references in pinned order, exact paths,
formats/status/reasons, the missing `geoip:bing` row, SHA-256 syntax and
sizes, aggregates, and exact blocked redistribution/license declarations.
The GitHub CN audit workflow independently verifies its emitted report.

A report being well-formed **does not** prove that its digest matches actual
bytes, that the data may be redistributed, or that runtime CN is usable.
A new secure asset-root audit, approved legal provenance, complete licensed
offline resources, and independent Core DNS/routing traffic are still needed.
No installation/activation, TUN, subscription/ISP routing or rights bypass
is introduced. Real restore/#59 and 72h stability remain MVP blockers.
