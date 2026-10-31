# ADR 0115 — Read-only, bounded dormant rule-bundle orphan inventory

- Status: **M4 internal inspection prerequisite only**; not cleanup, authentication, restore, activation or portable resource import.
- Extends ADR 0114 without changing SQLite schema v18 or any on-disk data format.
- Linux ordinary-user process; no TUN; original CN 28 groups, Custom → GeoSite → GeoIP → ACL → FINAL; never create a subscription/ISP routing layer.

## Scope and decision

ADR 0114 atomically publishes a *private, inactive rules-only* directory. SIGKILL may leave a pending partial directory, and a power loss around the rename/parent-fsync boundary may leave an uncertain final directory. The publisher must refuse such ambiguous roots, but there was no bounded diagnostic for an operator to identify the obstruction without inspecting files manually.

Add internal `backupclosure.InspectDormantRuleBundles(ctx, live)`:

1. Derive the sole allowed target from the authoritative SQLite store path: `<state-db-parent>/inert-rule-bundles`. Never accept caller-supplied arbitrary folders, archives, names, plaintext or secrets. Require a pre-existing 0700 UID-owned non-symlink directory and take the same exclusive stage-parent `flock` as the publisher.
2. Inventory at most 16 entries. Recognize only exact final `.ktui-inert-rules-v1-<64-lowerhex>` and canonical Go-created pending `.ktui-inert-rules-pending-<6..32-alnum>` names. Unknown entries, links, non-private directories and limit overflow cause **a whole-report refusal**, not a partial trusted result.
3. Inspect no more than 128 canonical `<64-lowerhex>.json|.srs` regular files per scope. Require no symlinks/hardlinks, UID ownership, private file modes and a bounded 128 MiB per-scope byte budget. This phase deliberately does not open rule content for hashing; it only inspects metadata and namespace shape.
4. Reopen fresh directory descriptors and repeat all entries and inode metadata after a package-private fault boundary. Require exact matching file and directory identities, recheck the stage root path and live SQLite inert-journal inventory; return an error and **no report** on drift or cancellation. Flop between runs or same-UID actors after return remains out of scope.
5. Return only per-scope name SHA-256, phase (`pending` or `published_untrusted`), rule-file count, size, pending/published totals and a count of prepared inert-journal rows. No physical path, archive key, file data, executable, domain pattern or runtime config may be returned. `RuleBytesVerified=false`, `RestoreSupported=false` and `RestoreReady=false` on every successful report.
6. Neither a final-looking name nor a match to the journal count authenticates anything. An explicit future reader must independently verify complete ciphertext HMAC, inventory, source bytes, live journal/CAS and target directory under new leases before considering any separate cleanup/import protocol. **There is no unlink/rename/adoption/cleanup API in this ADR.**

## Tests and non-goals

- Regression fixtures cover empty root, completed rule-only bundle, empty crash-pending scope, unknown entries, symlink replacement, late directory rename, file mutation, bad modes, budget overflow, public or missing stage root, cancellation, and ensuring inspections do not remove any content.
- A failure to inspect blocks further inference; it does not trigger garbage collection, adoption or opening a restore path.
- Restoring old SQLite, active rule publication, credential migration, Core Check/Activate/Verify, rollback-of-rollback, crash/power-loss simulation and T15/T23 remain unsatisfied. PR #1 stays Draft, and no user-facing backup restore command is offered.
