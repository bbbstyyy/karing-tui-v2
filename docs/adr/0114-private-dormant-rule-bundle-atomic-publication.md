# ADR 0114 — Crash-safe, inactive rule-only bundle publication

- Status: **M4 internal storage prerequisite only**. Not recovery, application, resource activation, Core execution, or a durable cross-restart lease.
- Builds on ADR 0108–0113: journal-bound ciphertext candidate, authenticated archived SQLite/schema/profile, anonymous pinned resources, portable path preview, read-only destination audit.
- Schema remains **v18**. Linux ordinary-user, no TUN, original CN 28 groups and Custom → GeoSite → GeoIP → ACL → FINAL. Subscription/ISP routing remains removed.

## Problem

ADR 0113 retains fully authenticated rule and approved-Core bytes in anonymous Linux `O_TMPFILE` descriptors only during the process lifetime. They vanish after Close, SIGKILL or restart. ADR 0111's rebinding is purely hypothetical; ADR 0112 never writes a prospective target directory. Before designing true atomic resource import, we need to prove **all-or-none durable publication of rules to a completely inactive namespace**, while retaining the original ciphertext and runtime generation without any Core or SQLite restoration.

Publishing files one by one into a live `core/rule-sets` tree would expose a partial generation and invite resource/route mixing. Blindly linking the ADR 0113 source descriptors would also invalidate their `nlink=0` guarantee and may require Linux capabilities. This decision permits only a private, explicit, non-active staging directory and publishes its **directory entry atomically** once all resources are copied and verified.

## Decision

Add internal `InertPinnedRestoreResources.StageDormantRuleBundle(ctx, stageParent, key)`, which returns an audit-only `DormantRuleBundleReceipt` with `RestoreSupported=false` and `RestoreReady=false`.

1. Caller supplies an **existing, separately owned 0700** Linux staging parent; it cannot overlap the candidate ciphertext namespace or anonymous scratch path. Reverify the pinned source's complete HMAC/SHA/SQLite/schema/profile, exact v18 pending journal, current Applied/LKG/declaration/selection/Core CAS, source anonymous file digests and scratch identity while holding the pinned child mutex and ciphertext parent flock throughout.
2. Acquire a separate exclusive `flock` on the private stage parent. Refuse unexpected entries, symlinks, permissive directories and any leftover `.ktui-inert-rules-pending-*` scope. Permit a maximum of eight complete bundles. **Do not silently reclaim** incomplete or unknown scopes. Each final scope is deterministic for its authenticated ciphertext SHA-256 (`.ktui-inert-rules-v1-<archive-sha>`), and a second attempt cannot overwrite it.
3. Create one private, not-yet-published `.ktui-inert-rules-pending-*` directory (0700). Copy only canonical inventory-listed `<sha>.json|.srs` **rule content**, via `openat(O_EXCL|O_NOFOLLOW|O_CLOEXEC)`, from authenticated, still-anonymous pinned FDs. Each newly written rule is 0600 while copying and 0400 after independent SHA/length verification and file fsync. The source pin keeps `nlink=0`. **Never copy or publish the historical Core executable or credential-bearing SQLite**.
4. Within the pending 0700 namespace, hash each file a second time through parent-relative no-follow FDs, check one hard link, current UID, non-executable mode, exact canonical name/size and original inode. Reopen the directory via a fresh descriptor and require **exactly** the expected list of filenames (no additional entries). Fsync the pending directory.
5. Repeat full private-directory entry and file digest/inode checks at the last fault boundary; then recheck the source pinned FDs and complete original encrypted-candidate/journal/live CAS, with the ciphertext flock still held. Publish the entire prepared directory using Linux `renameat2(RENAME_NOREPLACE)`, followed by directory and staging-parent fsync. The final scope is **not referenced by any live configuration**.
6. Return only nonsecret source/inventory hashes, rule count/bytes, a hash of the scope name, `Inactive=true` and both restore flags false. The private bundle survives closing the anonymous FDs, but **does not itself become a trusted resource handle or restoration permit**. A future reader must independently authenticate every resource and the exact journal again.

### Crash and cleanup contract

- **Before rename:** no complete bundle name exists. A process crash may leave a visible but **private, explicitly pending** directory with partial rules. A new stage refuses to proceed in a root containing such a scope. No automatic adoption or unsafe recursive removal is provided.
- **After rename, before parent fsync:** the atomic filesystem namespace commit has occurred, but post-crash durability may be ambiguous. The function returns an error if fsync fails and **never deletes** a potentially published bundle. An explicit recovery/inspection tool must later distinguish these states.
- **Ordinary in-process failure:** cleanup inspects and deletes **only exact inode-identified names created by this call**. If an unrelated actor has added/replaced entries or swapped the directory inode, cleanup fails closed and leaves an ambiguous scope for manual inspection; it never removes unknown paths recursively.
- The published bundle remains an inert private directory of rules, **not** the final active `core/rule-sets/sha256` layout. It is neither a durable resource lease nor usable as a cross-restart trust shortcut. No credential SQLite contents, session secrets, or executable Core is persisted here. Rule content itself may reveal user-authored domain patterns and is therefore kept under strict private permissions.
- Same-UID/root actors may still race filesystem operations. The parent flock coordinates only cooperating users of this internal primitive. A future restore writer must reacquire target FDs, validate all bytes again, persist an independent authorized journal and use an operation-gated CAS transaction; the bundle name alone proves nothing.

## Test and release gates

- Unit tests confirm one complete atomic private rule bundle, no historical Core, no live rule or database changes, correct 0400 content, persistence across FD lease Close, repeated no-replace collision refusal, initial source FD preserved at `nlink=0`, and private pending cleanup on injected pre-commit fault.
- Reject wrong key, canceled request, unsafe/missing/symlinked stage root, unknown/stale pending directory, live selection/journal drift, changed source FD and late staged file/directory replacement. Stage must serialize with concurrent pinned child and ciphertext parent Close.
- The real repository-approved sing-box integration fixture now exercises inactive **rules-only** bundle creation while verifying the historic Core remains anonymous and unexecuted.
- **Remaining blockers:** explicit orphan inventory/abandon and safe cleanup across crashes; stage-bundle reauthentication after restart; durable resource pin/atomic *active* publication; isolated credential/database migration; compile-equivalent portable JSON; same-transaction restore write CAS; Core Check/Activate/Verify; rollback-of-rollback; T15/T23 SIGKILL/power-loss injection; offline CN resources/licensing; and 72h/7d/30d soak. Keep PR #1 Draft and all user-facing restore entrypoints disabled.
