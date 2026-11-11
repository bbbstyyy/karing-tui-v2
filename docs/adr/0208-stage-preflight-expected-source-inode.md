# ADR 0208 — Bind Stage's first HMAC pass to its pre-pinned original source file inode

Status: Draft M5 T15/T23 source-custody hardening; stacked on ADR 0207.

## Gap

ADR 0204 pins the ORIGINAL source archive directory and its exact encrypted
leaf descriptor before Stage preflight, retaining both through quota
reservation, candidate copy and post-copy checks. ADR 0206 makes Stage's
preflight borrow the already-pinned parent fd; ADR 0207 retains the file fd
from the first complete HMAC pass through inventory and SQLite replays.

However, the first preflight HMAC still `openat`-opens the encrypted filename
without comparing that inode to the file descriptor Stage pinned EARLIER.
An uncooperative same-UID process can rename the original 0600 leaf within
its same owner-private parent and replace it with a byte-for-byte identical,
legitimately HMAC-authenticated file inode. The initial HMAC would read the
replacement even though Stage would later reject on its end-of-preflight
source inode recheck. Stage's original file pin needs to constrain
**which bytes may be read during the FIRST HMAC pass**.

## Decision

- Add an internal `preflightInertArchiveAtParentExpectedFile` overload that
  borrows BOTH the already-pinned source parent fd and the original source
  file fd. Stage alone supplies the expected file; standalone Preflight and
  existing borrowed candidate Verify/Reopen APIs remain compatible.
- Add `verifyInertArchiveAtParentExpectedFileProbed`, preserving the
  original verification helper signatures as wrappers. It opens a separate
  read-only `openat` file fd for HMAC, then **before reading any ciphertext**
  requires it and Stage's earlier fd to name the SAME original inode,
  with exact current path, UID/0600, single link, length, mode, mtime
  and parent inode constraints. Recheck after the complete HMAC/EOF read.
- A successful HMAC still transfers only its own file fd to the ordinary
  three-pass Preflight, as required by ADR 0207. Stage retains ownership of
  its earlier original file descriptor, without closing it or changing its
  read offset. The final Preflight also checks the Stage expected fd against
  the verified HMAC fd and canonical path. Stage's separate source checks
  before and after preflight/copy remain in place.
- Preserve full encrypted AES-CTR/HMAC/resource/SHA/EOF checks and independent
  inventory/SQLite replay, memory-only SQLite schema/domain verification,
  bounded timeouts, public receipt shape and disabled restore flags.
  No additional locks, retries, plaintext copies, public API changes,
  core execution, or persistent state mutation.

## Linux tests

- With real valid ciphertext, a pre-pinned original source file fd, and
  pre-HMAC deterministic hook, swap ONLY the leaf name inside the original
  directory with a different 0600 inode containing byte-identical,
  authentically encrypted bytes. Preflight must refuse with an empty
  report, leaving both versions, their inode identities and a sentinel
  untouched, without closing either caller fd. An ordinary independent
  Preflight of the replacement is still valid, proving rejection is custody
  rather than cryptographic failure.
- A healthy expected-file Preflight must match ordinary read-only results,
  leave `RestoreReady=false` and `RestoreSupported=false`, preserve
  original caller fd ownership and read offset, and reject a different
  but valid file fd passed as the expected source.
- Private first-HMAC verifier on a replacement must not return a retained
  descriptor on refusal. Actual Stage injected immediately after its first
  `source_inode_pinned` checkpoint must refuse leaf substitution before
  candidate reservation, leaving no candidate or modified ciphertext.

## Risks and release gate

This binds a single operation's HMAC source to Stage's existing original
inode, not an atomic compare-and-open against an adversarial same-UID
process swapping directory entries between syscalls. It cannot establish
persistent multi-process source provenance or prove Issue #59's
intermittent candidate `create_scope` refusal root cause.

Issue #59 remains OPEN. No live restore, candidate auto-GC, T15/T23/T20/T25
acceptance, licensed CN offline rules or release approval.
Keep unprivileged Linux without TUN, Karing five-layer routing without
subscription/ISP source routing, approved native Core and stable `main`.

Merge only after PR #87 (ADR 0207) completes final exact-head CI and merges,
then retarget/revalidate this Draft on `feat/m0-m1-foundation`; require
ordinary CI, all four Go Race shards, Managed Core integration, and native
amd64/arm64 Core Provenance to pass on the final exact integrated head.
