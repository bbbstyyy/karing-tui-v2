# T15 prepared-journal checkpoint: actual application Store in a disposable guest

**Status: lab fixture only. No real virtual stop, reboot, physical power failure or T15/T23 pass is claimed here.** Read [ADR 0130](../adr/0130-t15-real-prepared-journal-guest-lab.md), [host virtual-stop guard](t15-t23-virtual-powercut-lab.md) and [guest post-stop SQLite subset](t15-t23-guest-sqlite-replay.md) before any operation.

## Scope and hard safety conditions

`TestT15DisposableGuestPreparedBoundary` uses the repository's **real Go v18 storage code** to commit an initial Applied/LKG and prepare a second **unactivated** journal entry. It only compiles into Linux test binaries, never the product daemon, TUI or CLI. The ordinary Go test job skips its long-running mode. Its standalone deterministic unit counterpart verifies this boundary on a disposable temporary SQLite directory in normal CI.

The long-running guest mode MUST ONLY run against a **newly cloned VM with no personal data or existing state.db**. Use non-root guest execution and a new nonce. Never try it on the host user account, a production system, normal existing proxy profile or mounted personal/home/credential files. The VM name must begin `ktui-t15t23-disposable-`, and UUID must be its actual full lowercase libvirt UUID. The guest's dedicated `$XDG_STATE_HOME/karing-tui-v2` and `recovery-lab/ktui-powercut-disposable-<nonce>` must already be current-UID 0700 and entirely non-symlinked.

The fixture refuses any existing SQLite main DB, WAL, SHM or rollback journal. It uses an advisory state-directory lock; such locking cannot defend against an arbitrary uncooperative process. It may leave a persistent isolated test DB and phase marker after interruption. **Never automatically delete or reuse these files**; preserve the disk image for independent inspection.

## Example disposable guest procedure

Inside an isolated guest only, from the repository checkout:

```sh
# Set only after provisioning an empty throwaway VM and a separate
# host/guest test-witness mount with matching owner/UID.
export XDG_STATE_HOME="$HOME/.local/state"
domain=ktui-t15t23-disposable-lab1
uuid=01234567-89ab-cdef-0123-456789abcdef
nonce=0123456789abcdef0123456789abcdef
case=T15-prepared-journal

install -d -m 0700 "$XDG_STATE_HOME/karing-tui-v2"
install -d -m 0700 "$XDG_STATE_HOME/karing-tui-v2/recovery-lab"
install -d -m 0700 "$XDG_STATE_HOME/karing-tui-v2/recovery-lab/ktui-powercut-disposable-$nonce"

# Make absolutely sure "state.db", "state.db-wal" and "state.db-shm"
# do not exist before continuing. Never delete an existing DB to force
# the test to work.
export KTUI_LAB_NONCE="$nonce" KTUI_LAB_DOMAIN="$domain" KTUI_LAB_UUID="$uuid"
export KTUI_T15_GUEST_ACK="PREPARE:$domain:$uuid:$case:$nonce"
go test -count=1 -timeout=0 -run '^TestT15DisposableGuestPreparedBoundary$' ./internal/storage
```

The final command intentionally remains running only **after** a real production Store transaction commits an original Applied/LKG generation and a new `prepared` journal row, the store closes, the state directory is fsynced, and an exact owner-0600 fsynced `ready-<nonce>.txt` is published in the private witness folder. It logs only a nonsecret phase/nonce/attempt number. If any step fails, **do not force the VM stop; inspect the isolated failed lab directory**.

While this process is blocked, from an independent guest shell run ADR 0129's read-only `--mode capture` and save the emitted baseline SHA **outside** the guest. Its captured state includes an active `prepared` journal: this is expected, not yet a recovered state. The host ADR 0128 `--execute` operation, if the operator explicitly permits it, checks the same case/nonce/VM UUID and phase marker before it abruptly stops that particular disposable VM.

After a manual reboot, keep the user service and sing-box Core stopped. First obtain independent evidence of the unchanged v18 SQLite WAL/journal, original Applied/LKG, route/selection intent and the exact prepared attempt. ADR 0129 `--mode verify` currently **refuses** an unreconciled active prepared journal, even if all visible hashes match. This is correct: a manual hold is not recovery success. A separate explicit test-only call to the production `RecoverInterrupted` on this isolated SQLite can then mark the prepared attempt as interrupted (the normal CI unit fixture exercises this), but the original pre-cut subset baseline will no longer match after that mutation. Record the complete before/after sequence in an externally preserved, independent evidence log.

Do not use the results to authorize history activation, credentials import, proof cleanup, automatic GC, real Core changes or release. Actual T15 closure requires all transition points, rollback-of-rollback, host/guest block cache behavior, physical power-cut replay, Core traffic verification and the full safety/soak matrix. T23 is unaffected.

## Automated CI coverage

A regular, bounded `TestT15PreparedGuestStoreAndReadyMarkerAreTestOnly` runs actual `storage.Open`, `PrepareApply`, `CommitApplied`, fresh `PrepareApply`, reopen and `RecoverInterrupted` on a private temporary database; it verifies the original generation remains Applied/LKG and the second attempt was never activated. It also requires exact byte-for-byte host-compatible phase marker, owner-0600 file and non-overwriting behavior. The long-running, operator-acknowledged guest mode is skipped in CI and never invoked by `make test` or Race without all exact explicit guest env conditions.

**No actual VM was powered off by this development slice.**
