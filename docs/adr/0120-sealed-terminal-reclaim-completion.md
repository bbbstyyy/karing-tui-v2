# ADR 0120 — HMAC-sealed terminal completion of explicit inactive-rule reclamation

- **Status:** M4 internal-only terminal audit prerequisite; no automatic cleanup, metadata deletion, backup restore or Core activation.
- Extends ADR 0114–0119; SQLite v18, source encrypted archive and live declaration/Applied/LKG/selection/Core runtime formats are unchanged.
- Linux ordinary UID, no TUN. Preserve original CN 28 preset groups and Custom → GeoSite → GeoIP → ACL → FINAL; subscription/ISP routing layer remains excluded.

## Problem

ADR 0119 can durably authorize and unlink exactly one *inactive private* rule per explicit request. After the last rule is absent, its signed plan and every per-leaf HMAC/fsync intent are still the evidence that these absences were authorized. Recursively removing the reclaim directory or deleting those markers immediately would destroy crash-recovery provenance. A complete last-leaf report is only momentary and not a durable terminal state.

Decide to **seal completion before attempting any final metadata removal**. Introduce an immutable, keyed, domain-separated completion marker in the same private `.ktui-inert-rules-reclaim-v1-<ciphertext-sha>` directory. It is an audit barrier and not a permission to unlink the plan, intents, root or archive.

## Decision

1. `InertRestoreResourceLease.SealCompletedDurableReclaim(ctx, key, expected)` is an explicit internal method, not invoked by daemon/TUI/CLI. The caller supplies a prior `DurableRuleReclaimProgress` only as an optimistic expectation. Require `AllRulesUnlinked=true`, rule/intent counts equal the authenticated original inventory size, all referenced SHA-256 strings well formed, and both restore flags false.
2. Reacquire/revalidate the original ciphertext lease under its mutex and held candidate-directory `flock`, requiring the exact still-**prepared** v18 journal ID, original 32-byte key, full ciphertext HMAC/SHA, encrypted inventory, SQLite/schema/profile verification and unchanged live Applied/LKG/declaration/selection/Core CAS. Derive only the canonical `<live-db-parent>/inert-rule-bundles` root, hold its exclusive private directory `flock`, and open the exact `reclaim-v1` scope using parent-relative no-follow FDs. No caller path reaches a deletion API.
3. Reopen the authenticated ADR 0119 immutable plan, including its HMAC, exact archive/inventory SHA and directory device/inode. Scan the entire scope under fresh directory descriptors. There must be **zero original rule leaves**, exactly one valid private 0400 intent for **each** original rule, and no unknown names or files. Every intent must authenticate via the original plan digest, rule index/name and original key. Recheck the complete scope and live CAS before committing.
4. Build deterministic canonical JSON for `.ktui-reclaim-complete-v1` binding format version, archive SHA, inventory SHA, plan SHA, still-prepared journal ID, reclaim directory device/inode, original rule count and sum of original rule byte lengths. HMAC-SHA256 it with the original supplied archive key and a **separate domain string** from the plan and per-leaf intents. Publish with `O_CREAT|O_EXCL|O_NOFOLLOW`, require current-UID 0400 one-link regular file, file `fsync` and scope/root `fsync`. Never overwrite an existing, broken, linked or already-sealed marker.
5. After publication, a separate **terminal-only** scanner must read all entries afresh. It allows **only** the exact complete plan, all original HMAC intents and this exact signed completion marker. No rule bytes, executables, extra SQLite, symlinks, permissive files, wrong digests or missing intents. Repeat the entire scan, inode metadata checks and live CAS; return only plan/completion/archive/inventory digests, original rule count and signed absent byte sum.
6. `InertRestoreResourceLease.InspectSealedDurableReclaim(ctx, key)` performs this terminal-only authentication after process restart and lease reacquisition. Previous ADR 0119 `InspectDurableRuleReclaim` and `UnlinkNextDurableReclaimRule` deliberately reject the new completion marker as an unknown entry; a sealed scope can never silently resume deletion.
7. Both APIs return `CompletionSealed=true`, `MetadataRetained=true`, `RequiresRevalidation=true`, `RestoreSupported=false` and `RestoreReady=false` on success. The report is **not a permanent inode pin or permission** to remove the remaining audit data. No `unlinkat`, `rmdir`, move, import, Core check/activate, journal phase change or restore generation can occur in these methods.

## Crash and adversarial behavior

- **Before marker creation:** all original rule bytes are already accounted for by the signed plan/per-leaf intents. Failure creates no terminal marker.
- **After marker file fsync but before directory fsync:** SIGKILL or power loss can leave uncertain publication. Return **no success receipt**. If a valid marker is visible after process restart, an independent complete reauthentication may inspect it; this is not a claim that a real power outage persisted the directory entry.
- **After successful scope/root fsync:** the signed completion evidence is retained. A duplicate seal attempt must refuse rather than overwrite; ordinary pre-completion inspection and deletion must refuse the unexpected terminal marker.
- Same-UID non-cooperating path replacements remain outside the guarantee of `flock`; double scans, O_NOFOLLOW, private permissions, file/inode checks and complete authenticated contents fail closed on observed tampering. No reports leak rule text, absolute filesystem paths, the archive key or credential SQLite plaintext.
- Failure after any marker publication is never repaired by blind rename, unlink, `RemoveAll`, TTL/PID garbage collection, or auto-adoption.

## Regression matrix and release gates

- All-leaf prerequisite, bounded count/bytes, exact expected progress, plan and intent HMAC, duplicate seal, old-reader rejection and non-mutating Applied/LKG/journal/live Core checks.
- Refuse wrong key, canceled/closed lease, altered archive/plan/count/byte expectation, surviving leaf, missing intent, malformed/symlink/public marker, unknown extra entry, stale selection/journal and late injections.
- A Linux subprocess independently reacquires the original ciphertext lease, writes the terminal marker and is SIGKILLed before scope directory fsync. A new independent lease rechecks the visible evidence and confirms all original plan/intent metadata persists.
- Managed, repository-approved real Core integration seals the private completed rules-only scope without copying/executing Core or mutating live rules.
- **Still blocked:** durable operator-reviewed metadata/tombstone retention and final directory deletion, actual power-loss fault replay T15/T23, safe old pending-orphan cleanup, full restored SQLite/credential import, target rules publication, complete Core Check/Activate/Verify, multi-layer rollback/rollback-of-rollback, CN offline resource licensing and 72h/7d/30d soak. No user-facing backup, restore or cleanup entrypoints; PR #1 stays Draft.
