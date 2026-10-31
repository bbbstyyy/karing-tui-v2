# ADR 0100 — Lease-safe encrypted archive temporary recovery and non-destructive retention

- Status: **M4 internal-only hygiene/retention precondition**, not an exported product backup or restore workflow.
- Follows ADR 0094–0099 and `docs/plan.md` §§13, 18 and 20.
- Linux user mode; no TUN; unchanged CN 28 presets and Custom → GeoSite → GeoIP → ACL → FINAL. No subscription/ISP routing.

## Ownership and compatibility boundary

The internal sealed-archive writer now creates only `.ktui-sealed-v2-<random>` temporary ciphertext files in an existing UID-owned private (0700) archive directory. The writer obtains a *directory* `flock` for the creation-to-file-lock handshake, then holds a separate exclusive file-descriptor `flock` for the full encryption, fsync, no-replace hard-link publication, temporary-name removal, and parent fsync sequence. Active files are not recoverable or deletable by another writer. The writer never drops the file lock between completing encryption and publishing the ciphertext.

`ReclaimAbandonedSealedArchives` uses the same parent lock for a bounded two-phase scan/cleanup. It only recognizes the **new v2** temporary namespace, verifies no-follow regular-file mode 0600, UID, inode, size and link count, obtains an independent nonblocking file lock, and scans every directory entry before deleting any file. An active file is skipped; an unlocked single-linked v2 temporary may be unlinked relative to the locked parent directory fd and the directory fsynced. The process-death release of Linux `flock` makes failed, abandoned ciphertext files reclaimable without a PID heuristic or age guess. No plaintext is read, decrypted, or written.

Legacy `.ktui-sealed-*` files from before this lease protocol have **no trustworthy lock evidence**, so they are never removed automatically. Unknown filenames, symlinks, unexpected permissions/ownership, oversized files, too many entries, and ambiguous two-link temporary files left by an interrupted hard-link publication **fail closed** for operator investigation. A same-UID adversarial rename/ABA remains beyond the bounded trusted-user scope. There is no recursive deletion and no TUI/API recovery trigger. Best-effort process-local cleanup continues to handle normal writer failure.

## Retention is refusal, not pruning

`InspectSealedArchiveRetention` reports bounded counts only. Up to **8** complete `.ktbackup` entries and **32** temporary candidates may appear in the dedicated private archive directory; complete ciphertext storage is limited to `8 × MaxSealedArchiveBytes`. Before a new write, the system opportunistically reclaims only safe orphan v2 temporary files, then checks retained count, projected space and available blocks. At capacity it refuses the new write; it never overwrites, prunes, deletes, renames, decrypts or changes completed archives. Completed-file enumeration verifies *metadata only*, not authenticity. The operator must decide future removal; there is currently no automatic retention task, delete API or CLI. Backup names and contents are not returned in the count-only report.

## Evidence, failure and release gates

Tests cover a live child process holding the leased file across a scavenger invocation, SIGKILL release and later reclaim, retained authenticated ciphertext survival, full retention refusal, cancellation, and fail-closed legacy, symlink, hard-link, mode, size, unknown-entry and over-budget cases. The normal CI and pinned real-core integration workflows must still pass.

This is **not a durable encrypted-backup format approval or restore permission**. Completed files have no managed index, key escrow, cryptographic signature, portable migration contract, archival GC, durable generation lease, restore transaction or rollback-of-rollback. T15/T23, CN offline license/resource closure and 72-hour/7-day/30-day stability gates remain open. `restore_ready=false` and `restore_supported=false` remain unchanged.

An active temporary writer reserves one of the eight final archive slots and its **worst-case** maximum bytes. The creation-and-reservation check is serialized under the parent lock, so two concurrent writers cannot consume the same last slot. An aborted writer releases a reservation only after its v2 staging inode is safely reclaimed.
