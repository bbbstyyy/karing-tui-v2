# ADR 0084: Read-only confirmed generation inventory and recovery integrity audit

- Status: Accepted as an M4 recovery prerequisite; **NO operator-initiated rollback**.
- Platform: Linux user-space HTTP/SOCKS proxy, no TUN, no subscription/ISP routing layer.

## Problem

SQLite retains immutable compiled native generations, manifests and source maps. The retention policy keeps the most recent confirmed generations and archives compact apply history; older payloads may be pruned while their historical records remain. A historical revision number is therefore not evidence that a core can safely activate that generation. Manifest-linked rule-set files are separate private content-addressed filesystem resources. Their existence, ownership and SHA-256 must be checked independently of SQL.

## Read-only audit contract

`storage.ConfirmedGenerationRefs` enumerates only committed generations from the active journal and archived history, with distinct IDs, target config revision, whether a full payload is retained, descending order and an explicit truncation signal. SQL query/response sizes are bounded; failed, prepared and rolled-back candidates are excluded. A success audit never deletes, rewrites or keeps a generation alive.

`GET /v1/config/recovery/audit` checks at most twelve entries:
1. exact SHA-256 and bounded valid JSON for stored native config, compiler manifest and source map;
2. pinned compiler schema, self-consistent config hash and nonempty manifest declaration binding;
3. the immutable declaration revision is still available, matches the declaration SHA-256 over stored bytes and parses as a valid V1 model;
4. every manifest-listed local rule-set file has a known source/binary format, a lowercase SHA-256, an expected absolute path *inside the configured private content-addressed rule store*, valid private ownership/file type and matching disk hash, using the existing no-follow verifier.

Failure yields a generic status such as `payload_pruned`, `payload_hash_or_json_invalid`, `manifest_or_provenance_invalid`, `declaration_unavailable_or_invalid` or `rule_set_resources_unverified`; raw paths, matcher values, node passwords and native core JSON are not emitted. If stored bytes and external resource checks both pass, the status is `stored_integrity_verified_only`. Snapshot and declaration-head identity are read again after audit; an apply/declaration race returns 409 rather than a mixed report. The result is point-in-time evidence, not a lease against later retention or resource mutation.

CLI `config recovery-audit` enforces the typed API schema, bounded count, strict status enum and fail-closed `restore_supported=false` / `restore_ready=false` before printing JSON. No confirmation option or write variant exists.

## Why restore is still blocked

Successful stored hashes do **not** prove a historical generation is safe to activate today. The project must first verify selector-intent compatibility with the target generation, current routing mode and private-direct state, pinned runtime and core binary, dependency closure at the actual apply instant, and the full SQLite CAS/recovery journal transaction. A correctly functioning historical restore also needs check/activate/verify, an intact previous known-good core generation, and rollback-of-rollback failure injection. An audited but pruned generation has no immutable native payload to restore. Therefore every entry is deliberately `restore_ready=false`, and `restore_supported=false` is invariant. Existing apply-failure automatic rollback remains unchanged.

This neither closes the M4 backup/restore milestone nor T10 actual DNS detour observation, CN offline resource/license closure or M5 long-running release gates. The five-layer route order and subscription/ISP exclusion remain unchanged.
