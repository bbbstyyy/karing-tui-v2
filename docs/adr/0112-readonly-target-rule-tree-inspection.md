# ADR 0112 — Read-only, descriptor-pinned portable destination rule-tree inspection

- Status: **M4 internal safety prerequisite**; does not grant restore, durable resource ownership, an import or core activation.
- Builds on ADR 0108 journal-bound ciphertext flock, ADR 0109 immutable archive lifecycle audit, ADR 0110 anonymous materialization and ADR 0111 in-memory native path relocation preview.
- Linux ordinary-user only; SQLite schema **v18 unchanged**. CN 28 groups, Custom → GeoSite → GeoIP → ACL → FINAL, no subscription/ISP routing layer, no TUN.

## Problem

ADR 0111 computes hypothetical portable paths from the authenticated historical native manifest without consulting the target filesystem. A lexical path may instead resolve through untrusted symlinks, permissive directories or existing content-addressed names whose bytes no longer match the archive. Treating a preview hash as a file import capability would risk executing corrupted rule data or overwriting an unrelated live resource. A separate, non-mutating filesystem collision and directory-identity audit is needed before future durable restore work.

## Decision

Add `InertRestoreResourceLease.InspectPortableTargetRuleTree(ctx, targetStateRoot, key)`, internal-only and synchronous. The target root is **existing**, clean and absolute. When the authenticated archive contains rules, `core/rule-sets/sha256` below that root must already exist. Nothing is auto-created, repaired, relabeled, hardlinked, installed or executed.

1. Hold the existing candidate-directory `flock` and `InertRestoreResourceLease.mu` for the **entire inspection**. Reauthenticate the complete encrypted archive and in-memory historical SQLite/schema/profile, and validate the exact pending v18 journal record and current Applied/LKG/declaration/selection CAS before and after the filesystem read.
2. Open `/` and **every** subsequent target path segment with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` using `openat` relative to the previously pinned directory descriptor. Intermediate ancestors must be real directories, not symlinks. The selected state root and its `core`, `rule-sets` and `sha256` directories must have mode **0700**, belong to the current UID and retain their opened inode identities. The encrypted-candidate namespace is explicitly excluded.
3. Only canonical `rule-sets/sha256/<authenticated-sha>.json|.srs` names can be inspected, using each signed inventory entry's exact relative name, SHA-256 and bounded declared size. A missing file is reported **missing**, not considered imported or safe to activate. An existing file must be a regular file, UID-owned, exactly 0400/0600 and non-executable, have **one** hard link, exact size and SHA-256. Each file uses a no-follow relative FD; compare the parent-relative inode with the opened descriptor before and after hashing.
4. Repeat the full existing-file/absence check after all entries. Any same-content inode replacement, appearance of a previously missing file, symlink insertion, content change, permission drift, root/ancestor/subdirectory rename or live journal/CAS change fails closed. Check all pinned directory identities again before and after the final live CAS.
5. Close all path descriptors before the call finishes. Return only archive and inventory SHA-256, a hash of the requested canonical root, existing/missing rule counts, authenticated existing-byte count, and `DirectoriesPinned`. The result always has `RestoreSupported=false` and `RestoreReady=false`.

The directory verifier deliberately imposes stricter 0700 owner-private requirements than general Linux paths and does not repair them. Only missing content-addressed file *entries* are tolerated; missing directory components are a hard stop. Existing aliases, any link count other than one, and even same-byte inode swaps are refused rather than silently accepted.

## Non-goals and race boundary

- This is **not** an atomic cross-filesystem snapshot, filesystem write CAS, stable resource lease or proof that the directory will remain unchanged after the method returns. FDs are immediately closed. Root or same-UID writers may race; a **future** restore writer must reacquire verified target descriptors and repeat all checks while committing under its own operation gate.
- We do **not** copy/overwrite files, persist decrypted SQLite or Core, install a temporary executable, stop/restart sing-box, remap subscriptions, rewrite the journal or mutate current/LKG/selection/declaration state. A missing rule cannot be supplied by this call.
- The trusted target rule-tree precondition does **not** establish permission to create a new generation or use the existing core. The approved Core remains pinned only by the separate ADR 0097/0110 contracts, and ADR 0111 remains an independently non-authorizing lexical preview.
- Full current-schema SQLite migration, durable target inode pins and atomic install, portable config recompilation, same-transaction restore CAS, T15/T23 crash/power-loss/rollback-of-rollback, complete CN offline resource/license closure and 72h/7d/30d stability validation remain required. PR #1 stays Draft.

## Verification

Unit tests exercise both absent and already authenticated files without creating a pathname; chmod drift, executable/public files, wrong-size/content collisions, hard links, symlinks, directories substituted for files, ancestor path alias, missing/unsafe directories, wrong keys and canceled context. Fault injection replaces identical-byte files and entire directory inodes, adds missing paths late, changes live selection, abandons durable journal and races lease `Close` against inspection. Real approved-core integration runs the same target-inspection step without executing or installing either Core or rules. These tests are gates for this **read-only** slice, not for enabling full restoration.
