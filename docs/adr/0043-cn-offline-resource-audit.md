# ADR 0043: Audit the complete CN offline rule-set closure before distribution

- Status: Accepted
- Date: 2026-10-06

## Context

The project plan requires an offline CN rule package that covers all 28 preset groups, including groups disabled by default, plus the CN region auto-append resources.

A distributable manifest must record logical reference, relative path, format, byte count, SHA-256, source repository/commit, core compatibility, and license provenance. Hash identity alone is not a license or trust decision.

Karing's pinned CN preset references 68 unique logical built-in rule sets after adding the two region refs. Cross-checking the exact pinned Karing application tree shows 67 corresponding built-in `.srs` files.

The sole dangling logical reference is:

- `geoip:bing`

The same file is absent from the currently inspected immutable `KaringX/karing-ruleset` generated commit. The last publicly inspectable Karing preset importer filtered built-in references against the available GeoSite/GeoIP/ACL code inventories before importing a rule. Therefore manufacturing a replacement `geoip:bing` file would not be an evidence-based compatibility fix.

The generated `KaringX/karing-ruleset` `sing` branch is also not an immutable build input: its workflow force-pushes generated content and checks out several upstream branches without pinning their commit SHAs. The generated branch does not carry a root license file, and the upstream data sources do not presently provide one simple repository-wide license statement that closes redistribution obligations for the combined package.

## Decision

The compatibility baseline for byte identity is the built-in asset inventory from the exact pinned Karing application commit:

- repository: `KaringX/karing`
- commit: `9d28b22fbbcca5818d147629aae151d49d4dcb7b`
- asset root: `assets/datas`

`preset.CNOfflineResourcePlan` derives the complete logical closure deterministically from:

1. every `rule_set_build_in` reference in the immutable 28-group CN snapshot;
2. `geosite:cn` and `geoip:cn` from the CN region auto-append policy.

It must produce exactly:

- 68 unique logical references;
- 67 file-backed candidates;
- one explicit `upstream_absent` entry, `geoip:bing`.

The relative path mapping is:

- `geosite:<name>` -> `geosite/<name>.srs`;
- `geoip:<name>` -> `geoip/<name>.srs`;
- `acl:<name>` -> `acl/<name>.srs`.

Qualifiers such as `@ads` and `!cn` remain literal filename components.

## Immutable byte audit

`cmd/cn-resource-audit` accepts only an explicit local asset root and:

- loads the pinned CN snapshot;
- derives the complete resource plan;
- requires every file-backed candidate to exist as a regular file;
- requires the known absent item to remain absent;
- streams every file through SHA-256;
- records exact byte count and SHA-256;
- emits deterministic JSON in resource first-use order.

The dedicated `cn-resource-audit` GitHub Actions workflow checks out the exact pinned Karing commit and runs the tool against `assets/datas`. Its output is uploaded as a short-retention audit artifact.

No runtime compiler or daemon path fetches these assets from GitHub.

## License boundary

The audit output deliberately contains:

- `distribution_ready=false`;
- `license_status=blocked_unresolved_upstream_data_licenses`.

This is not a placeholder to be ignored. The current evidence is insufficient to assert that the combined generated rule-set corpus can be redistributed in the project release package under one known license.

Observed provenance includes Karing's generated rule repository and multiple upstream data projects. The generated `sing` branch itself has no root LICENSE file, and its build workflow removes a build-directory `LICENSE` before publishing generated assets. At least one upstream source is GPL-3.0, while other relevant source repositories require separate license/provenance review.

Until that review is closed, the project may audit hashes and test user-provided/pre-staged resources, but it must not advertise a bundled CN offline rule package as distribution-ready.

## Dangling-reference behavior

`geoip:bing` is preserved in the immutable CN source snapshot for audit fidelity, but the offline resource plan marks it as upstream-absent.

A future runtime packaging layer must reproduce the evidenced Karing behavior for unavailable built-in refs rather than silently treating a missing required runtime artifact as DIRECT. The existing general declaration rule-set path remains fail-closed; only a preset-specific, audited compatibility transformation may omit this known dangling source reference.

## Capability boundary

`cn_preset_resource_audit=true` means the complete logical resource closure, immutable byte audit tool, and pinned baseline workflow exist.

`cn_preset_offline_bundle=false` and `cn_preset=false` remain intentional until:

- license/provenance review permits a concrete distribution method;
- the audited bytes are incorporated into a release resource manifest and package/update transaction;
- unresolved Linux `processName` compatibility is addressed.
