# ADR 0124 — Read-only retention review for sealed inactive reclaim evidence

- **Status:** M4 internal-only design checkpoint; non-destructive and permanently non-authorizing.
- Prerequisites: ADR 0119–0123. No schema migration from SQLite v18, archive-format modification, Core transition, TUN, automatic garbage collection, API/CLI/TUI restore or deletion.
- Continue preserving the CN 28 preset groups, five-layer Custom → GeoSite → GeoIP → ACL → FINAL selection, and exclusion of subscription/ISP routing.

## Motivation

A successful ADR 0123 detached audit authenticates the **history** recorded in the mirrored HMAC evidence, even if the original rule reclaim directory no longer exists. It cannot attest **current** source scope inode, rule absence, a persistent deletion authorization, power-loss durability, filesystem free blocks or consent to delete any metadata. ADR 0122's source-bound inspector can authenticate the original scope while it is still present. A future reviewed retention policy must not conflate these very different claims.

The current complete Race test run also exceeded 30 minutes on some GitHub runners despite another identical head passing. CI needs to remain reliable without silently skipping expensive encryption/SQLite failure fixtures.

## Decision

1. Add **internal read-only** `InertRestoreResourceLease.ReviewTerminalReclaimRetention(ctx,key)`. There is no caller-chosen path, cleanup token or action parameter. It first runs the detached ADR 0123 verifier, then attempts the source-bound ADR 0122 verifier, then independently **repeats** the detached verification, comparing both historical digests and all report fields. All verifiers demand the same original 32-byte archive key, full archive and logical SQLite authentication, still-prepared recovery journal and live Applied/LKG/declaration/selection/Core CAS. Fail closed if historical evidence or revalidation fails.
2. Report `SourceStatus="authenticated"` and `SourceProofsVerified=true` only if the source-bound verifier fully authenticates *all* original signed files and their identities, and its archive/inventory/plan/completion/anchor/mirror digests, counts, original documented byte lengths and mirror byte lengths exactly match the detached audit.
3. A missing, changed, unknown, invalid or inaccessible original source scope is classified uniformly as `SourceStatus="unverifiable"`, `SourceProofsVerified=false`, **never** as safely deleted or retired. If detached proof remains valid and the source-bound audit fails, the review can still return authenticated *history* to aid manual incident triage. It must not diagnose the reason for failure or expose source paths, ciphertext keys or rule payloads.
4. `HistoricalProofsVerified=true` documents signed past intent **only**. Both outcomes must have `RetentionPolicyApproved=false`, `PowerLossReplayVerified=false`, `PhysicalCleanupAuthorized=false`, `RequiresManualReview=true`, `RequiresRevalidation=true`, `RestoreSupported=false` and `RestoreReady=false`. These flags are literal restrictions, not an application permission that could be promoted by a caller.
5. The three verification passes are **not one atomic filesystem snapshot**; after return, directory entries may change. This report cannot pin inodes, authorize original plan/intent/completion or directory deletion, create an orphan adoption rule, claim fsync durability across a real power cut, or publish Core/rule resources. No metadata is created, modified or removed.
6. A dedicated integration fixture must show a source-present positive audit, the same signed history after moving (but **not deleting**) the source namespace, a new ciphertext lease after restart, no live SQLite/journal changes, wrong key, canceled context and stale live CAS refusal.

## CI stabilization: full rather than reduced Race coverage

- The original `go test -race -timeout 30m ./...` can time out in the expensive `internal/backupclosure` package on one runner while passing on an otherwise identical runner.
- The CI pipeline now separates ordinary format/vet/test/build checks from four independent Race shards. Each shard enumerates **all** `Test*`, `Fuzz*` and `Example*` top-level Go tests directly from the compiled `internal/backupclosure` package, assigns each exactly once by deterministic sorted round-robin, and runs the selected complete test and subtest tree under `-race -count=1 -timeout 30m`. Shard zero also covers **all other** Go packages under `-race`; there are no hand-maintained exclusions or test skips. The CI gate requires all four shards to pass.
- `make test-race` runs the same entire set of shards serially for developers, while GitHub Actions fans out the four shards in parallel *after* ordinary CI passes. Concurrency cancels obsolete same-branch Push/PR runs instead of competing with duplicate 30-minute suites. Retain clear logs identifying each shard's discovered test count.
- A successful CI run demonstrates automated Go concurrency checks, not T15/T23 physical power-loss or 72h/7d/30d soak.

## Still blocked

No operator-approved retention duration/expiry policy, safe final metadata unlink/rmdir with immutable evidence/rollback, unresolved pending orphan handling, T15/T23 power-fault replay, credential-bearing SQLite import, active rule publication, Core Check/Activate/Verify/rollback-of-rollback, CN offline resource licenses or full long-running soak. PR #1 remains Draft; no public backup/restore/cleanup endpoint is released.
