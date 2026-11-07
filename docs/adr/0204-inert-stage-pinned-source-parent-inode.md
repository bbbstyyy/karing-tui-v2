# ADR 0204 — Pin the authenticated source archive inode through inert candidate Stage

Status: Draft M5 T15/T23 security hardening; subject to stacked exact-head CI.

## Context

ADRs 0201–0202 pin the encrypted archive's private parent fd across
`VerifyInertArchive` and all three `PreflightInertArchive`
authentication/replay passes. `StageInertRestoreCandidate` originally
performed that complete read-only source preflight, reserved an
encrypted-only candidate directory, and **then** called
`copyInertCandidateCipher`, which reopened the source by absolute
pathname with `openSealedArchiveNoFollow(sourcePath)`.

An uncooperative same-UID process can rename the initially
authenticated 0700 source parent while the candidate parent is being
reserved, substitute an unrelated private directory holding identical
authenticated ciphertext, or move the SAME source file inode beneath
a freshly created private parent at the canonical path. A matching
SHA-256/HMAC and same child fd/path inode alone do not establish that
the copied bytes came from the initially authenticated parent
**and child inode** custody. A path-based source open is unnecessary:
the original source can remain read-only and pinned without holding
any exclusive parent flock across expensive work.

## Decision

- Before the first source preflight, open a non-flocked
  `O_DIRECTORY|O_NOFOLLOW` descriptor through the strict private
  parent validator, and open the exact sealed source leaf via
  `openat(source_parent_fd, basename,
  O_RDONLY|O_NOFOLLOW|O_NONBLOCK)`.
- Retain BOTH the source parent descriptor and the source leaf fd
  through full HMAC/inventory/SQLite source preflight, independent
  candidate-parent flock, new candidate scope creation, ciphertext
  copy, fsync and final candidate validation. Capture the original
  source inode identity, mode, size and mtime once.
- Verify parent fd/path identity, the exact child file fd/path inode,
  single-link/current-UID/0600 mode, original size and mtime before
  and after source preflight, immediately before a candidate
  ciphertext is created, and again after the bounded full-file
  copy/hash/EOF check. Do not reopen the source by pathname in
  the Stage copy routine. SHA-256 must equal the original authenticated
  source receipt.
- Keep the previous package-private `copyInertCandidateCipher`
  signature for isolated regression callers as a wrapper that
  opens its own pinned descriptors. Actual Stage invokes a new
  internal pinned-source copy variant with the descriptors captured
  **before** Preflight. No public API, persisted state or restore
  authority changes; the source file is never modified.
- On any source parent or child identity drift, fail with the
  existing inert candidate refusal sentinel. Existing guarded
  candidate cleanup remains responsible for removing only a
  proven original scope and file, never a substituted namespace.

## Linux regression contract

Using a healthy real encrypted archive, inject the existing
package-private Stage phase checkpoint at the beginning of
`cipher_copy` and again immediately after the destination ciphertext
fd opens. Rename the original source parent and substitute either
another owner-private 0700 directory or a symlink pointing to one
containing an identically named, byte-for-byte valid ciphertext.
All four cases must refuse, preserve the original source and foreign
copy/sentinel, and remove any proven locally owned failed candidate.

A second regression renames the original parent but moves the
**same original file inode** to the canonical source pathname in a
fresh private 0700 parent. The source's file stat and authenticated
digest still match; Stage must nevertheless reject changed parent
custody without touching either source or candidate parent.

Preserve the existing healthy Stage/Verify/Reopen/Discard and real
Core-compatible archive tests; no plaintext SQLite, archive
extraction, network access or automatic live state mutation occurs.

## Limits and release holds

This is a per-call source parent + file lease. It cannot establish
atomic directory-entry check-and-use against a malicious same-UID
process operating *within the original parent inode*, nor does it
persist custody across Stage invocations or daemon restarts.
The initial Preflight still runs its own short-lived parent fd:
cross-system-call checks cannot form a global atomic snapshot.
A same-UID attacker may leave an unreachable partial encrypted file
under the moved original candidate inode; never delete unknown
paths as remediation.

Issue #59's intermittent `create_scope`/candidate lease refusal
remains unresolved. ADR 0203 only improves test-only diagnostics.
Do not enable live restoration, automatic candidate GC, claim
T15/T23/T20/T25 acceptance, redistribute unlicensed offline CN
assets or declare release readiness. Linux ordinary-user no-TUN,
the Karing-style five-layer rule priority without subscription/ISP
source rules, native Core pin and stable `main` are unchanged.

Merge only after ADR 0202/0203 integrate, and the exact merged-head
ordinary tests, Go Race 4/4, Managed Core Integration and both
native Linux amd64/arm64 Core Provenance checks pass.
