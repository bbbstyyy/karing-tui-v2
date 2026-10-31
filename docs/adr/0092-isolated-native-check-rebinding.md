# ADR 0092 — Isolated native rule-set rebinding for historical core Check

- Status: **M4 non-activating internal compatibility step only**; manual historical restore stays disabled.
- Supersedes the dry-run-only limitation of ADR 0090 and ADR 0091 that `core Check` still consumed shared rule-set paths.
- Dependencies: ADR 0084–0091.

## Boundary

A stored historical generation's native config JSON and SHA-256 are immutable and bound by its SQLite journal and compiler-owned manifest. Replacing `route.rule_set[].path` in those persisted bytes would sever their hash/manifest relationship and could create a false positive applied generation. Conversely, invoking the existing `ManagedCore.Check` with an altered `Generation` would fail its required SQLite state validation or try to stage the different bytes under the same generation ID.

The new `rebindHistoricalCheckJSON` therefore operates **only after** exact historical declaration recompilation and source/manifest/source-map SHA verification, under the operation gate and after descriptor-pinned, independently copied source + applied + LKG rule resource closure validation. It reads bounded compiled native JSON using `json.RawMessage`, requires a one-to-one match of each local `route.rule_set` type/tag/format/original absolute path with the trusted manifest, and changes **only** the rule-set `path` field to the independently copied file in the locked snapshot. Duplicate/unlisted/mismatched resource bindings are rejected; DNS, routing rules, selector groups, outbounds and core-control options are not changed. The original bytes, manifest and source map remain untouched.

## Check-only staging and core adapter

`RuleSetSnapshot.StageNativeCheckConfig` stages exactly **one** bounded private native JSON file in the same flock-held ephemeral directory (a new `SHA256.json` name, owner-read-only, exclusive creation, fsync, exact digest/inode tracking, and the existing bounded orphan scavenging/cleanup). It checks that the total number and byte budget still fit after all rule copies. It never stages or binds the real generation.

For any historical generation with local rule sets, `CheckHistoricalGeneration` requires the optional internal `historicalIsolatedChecker`; it **fails closed** if the core adapter cannot perform an isolated check. `ManagedCore.CheckIsolated` separately revalidates the **original** immutable SQLite candidate/manifest/resources and the ephemeral JSON hash/path, then invokes the approved core's normal configuration-check runner directly on the isolated config file. It does **not** call `files.Stage`, `binder.BindConfig`, `Activate`, `Verify`, `Rollback`, restart, mutate LKG, or write the altered SHA into SQLite. Empty rule-set closure follows the existing unchanged strict `Check` path. The source/fallback pins, isolated copies and temporary native JSON are rechecked after Check and removed through scope identity-checked cleanup. The prepared journal candidate is separately marked failed and reclaimed via ADR 0089.

## Tests and remaining scope

Tests assert bytewise preservation of the original SQLite payload and SHA, all native JSON semantic fields except local rule paths, strict rejection of source SHA/tag/path/format mismatches, that the core receives **only isolated** local rule paths, absence of activation and live-state change, failure on an adapter without isolated support, and managed-core isolation with no `Stage` or binder calls even when original metadata is valid. A modified temporary native check file or mismatched original generation is rejected before core I/O.

This is **not** an activation permission. The ephemeral directory disappears when Check ends, and neither target nor fallback is durably leased across activation, daemon restart or rollback-of-rollback. The same-UID threat boundary, pathname ABA/short substitutions, persistent quota pressure, live DNS/routing readback and T15/T23 fault injection remain open. There is no API/CLI/TUI restore endpoint; `restore_supported=false` and all `restore_ready=false` remain unchanged. Linux ordinary-user operation, no TUN, CN preset, five-layer routing and subscription/ISP routing exclusion remain unchanged.
