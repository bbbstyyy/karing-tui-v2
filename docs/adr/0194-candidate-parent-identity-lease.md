# ADR 0194 — Preserve candidate parent identity through a live child lease

Status: draft implementation pending exact-head CI (M5 T15/T23 partial).

## Context

ADR 0191/0192 anchored initial parent inventory and Stage/Reopen child
opens to a locked parent fd. ADR 0193 separately pins the Stage parent
for post-copy durability. After the initial parent flock is released,
however, a live `InertRestoreCandidate` retained only the child
directory inode. The per-operation `verifyCandidateDirLock` validated
the leased child fd against its pathname, plus the current pathname's
private ancestors, without checking that the parent still referred to
the SAME inode that established the lease.

A same-UID actor ignoring the advisory flock can rename the original
parent, create a different owner-private 0700 parent at the old path,
and move the very same locked child directory into the replacement.
The child inode and ciphertext still match the open fd; the new
parent passes owner/mode checks. A path-only authenticated preflight
could otherwise accept this change of parent custody.

## Decision

- Record a separate `parentIdentity` (private `os.FileInfo`) when
  opening a child lease. For Stage and Reopen, obtain the parent
  identity from the already-flocked parent fd. For isolated internal
  path-based helper tests, use the verified parent pathname instead.
- Require the current canonical parent path to still name the
  recorded private directory inode before inspecting a candidate,
  after any empty-inventory early return, and at the end of
  ciphertext inspection. All Verify, Reopen and Discard paths use
  this same inspection boundary; no public API or new persisted
  lease format is introduced.
- Preserve the existing child inode, 0700, UID and single ciphertext
  leaf checks; all errors remain fail-closed without exposing paths.
  Reopen still independently reauthenticates archive content and
  SQLite logic and never grants restore authority.

## Regression evidence

1. Stage an encrypted candidate, confirm a healthy Verify, then
   rename its parent, create another private 0700 parent at the
   canonical path and **move the same locked child inode** into it.
   Verify and explicit Discard must fail closed. The source and
   retained candidate ciphertext remain unchanged.
2. Close a healthy staged candidate and Reopen with a test-only
   mutation immediately after the authenticated preflight, swapping
   the parent inode as above without changing child inode or archive
   bytes. Reopen must refuse. Neither source ciphertext nor the
   replacement parent's unrelated sentinel may change.

## Limitations and release holds

This pins parent identity only within the lifetime of the current
process lease. A fresh Reopen following process death must still
establish new parent identity because no persisted parent-identity
attestation exists. These are pre/post checks, not atomic pathname
stability guarantees against an uncooperative same-UID process.
The multi-pass HMAC/SQLite preflight itself is still path-based,
and Discard's directory-removal durability path needs independent
review. This does not resolve Issue #59, enable real restore/GC, close
T15/T23/T20/T25, settle CN offline resource licenses or authorize a
release.

Preserve Linux ordinary-user/no-TUN behavior, five-layer routing with
subscription/ISP routing excluded, approved Core and stable main.
Merge only after exact-head ordinary CI, Go Race 4/4, Managed Core
Integration and native Linux amd64/arm64 Core Provenance all pass.
