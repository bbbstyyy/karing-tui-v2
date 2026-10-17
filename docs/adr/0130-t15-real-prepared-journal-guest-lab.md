# ADR 0130 — Test-only real v18 T15 prepared-journal guest checkpoint

- **Status:** M4 test-only development slice. This does **not** close T15, T23, true electrical power-failure replay, backup restoration, Core activation or the release gate.
- Depends on the protected host VM stop in ADR 0128 and the still-unmerged guest SQLite subset auditor in ADR 0129. Adds **no production APIs or migrations**; tests are compiled only into Linux Go test binaries.
- Linux non-root and no TUN; CN original 28 presets, Custom → GeoSite → GeoIP → ACL → FINAL routing and subscription/ISP routing exclusion are unchanged.

## The gap

The host-side ADR 0128 script can accept an exact `ready-<nonce>.txt` label, but no project-controlled guest process yet actually reaches an application persistence boundary before publishing it. A human hand-created marker can never count as a real checkpoint. T15 requires crashing at actual journal transitions and verifying the original Applied/LKG generations are not confused with a new unactivated one.

## Decision

1. Add `TestT15DisposableGuestPreparedBoundary` in **`internal/storage/*_linux_test.go` only**. The test is always skipped in ordinary CI, or when the exact acknowledgement is missing. Destructive/long-lived mode requires an ordinary non-root guest, `CI` unset, canonical disposable VM name/UUID, lowercase 128-bit nonce, explicit absolute XDG state root and `KTUI_T15_GUEST_ACK=PREPARE:<domain>:<uuid>:T15-prepared-journal:<nonce>`. This is not available in a product CLI, daemon or API.
2. Refuse any **preexisting** `state.db`, `state.db-wal`, `state.db-shm` or rollback journal; the guest state parent and exact ADR 0128 per-nonce witness path must already exist, be current-UID 0700 and have no symlinked path components. A nonblocking exclusive advisory lock on that private state directory serializes cooperating test runners. These checks are not permission to reuse personal or production XDG state: the operator must run only a new disposable VM with a blank disk.
3. Use the application's actual `storage.Open` v18 store and **real** `PrepareApply → BeginActivation → BeginVerification → CommitApplied` methods to establish a committed baseline revision 1 with matching Applied/LKG, no daemon/Core activation. Then create a second generation with the production `PrepareApply` method and **do not** activate it. Require the second attempt is prepared, the live revision remains 1, Applied/LKG still reference the original generation, `CoreDesiredState=stopped` and `RecoveryRequired=false`.
4. Close the real test SQLite store, fsync the state directory, then publish the exact original ADR 0128 `ready-<nonce>.txt` bytes with descriptor-relative Linux `openat(O_EXCL|O_NOFOLLOW)`, owner-only 0600, file fsync + parent fsync and postpublication inode/content check. A failed/missing/duplicate marker never causes repair, unlink, auto-retry or a successful readiness statement.
5. Print only phase, nonce and prepared attempt ID and remain blocked while the **external**, separately consented host ADR 0128 tool may force-stop that disposable VM. The Go test itself never calls `virsh`, sends signals, restarts any process, opens proxy ports or touches a normal user's SQLite. An operator terminating the test without stopping the guest is **not** T15 power loss, even if a ready marker exists.
6. Ordinary `go test` and Go Race exercise a **bounded deterministic** version of the real storage/journal fixture inside `t.TempDir()`. Test existing DB refusal, exact marker bytes/owner-private mode, duplicate marker refusal and independent SQLite reopen + production `RecoverInterrupted` verifying the still-committed generation survives and the unactivated prepared attempt is safely marked interrupted. These tests do not spin forever or stop a VM.
7. A real run requires independent host VM disk identity, before-cut SQLite and rule/target inventory, exact checkpoint trace, VM stop witness, manual boot with daemon/Core kept off, independent postboot journal inspection, reconciliation, Core behavior and actual storage power-loss replay. ADR 0129's subset checker currently *refuses* any still-active prepared journal: that refusal is the correct manual-hold outcome, **not** completion of recovery.

## Explicit non-goals

No real T15/T23 pass flag, online credential import, ruleset activation, Core Check/Activate/Verify, rollback-of-rollback, deletion, orphan GC or production restore switch. There is no proof this guest-side fsync matches host electrical power failure semantics, no durable trust in noncooperating same-UID actors and no safe path to run this fixture on user data. CN offline license closure and 72h/7d/30d soak remain open. Outer PR #1 remains Draft, stable `main` untouched.

### Tighter disposable-state admission

The test also requires the private guest application parent to contain **only** the explicitly provisioned `recovery-lab` directory before any SQLite file is created. An unrelated app/user file causes immediate refusal; the input witness subdirectory must be **empty** before the journal fixture starts, preventing reuse of stale intent/observation/ready markers for a supposedly new nonce. The negative unit test verifies that unrelated preexisting user bytes are not deleted or overwritten. These are additional preconditions, not powers granted to clean up old state.
