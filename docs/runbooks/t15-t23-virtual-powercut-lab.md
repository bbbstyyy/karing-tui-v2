# T15/T23 — disposable VM abrupt-stop laboratory (pre-release)

**Status: infrastructure only; zero T15/T23 power-loss cases have been accepted by this runbook.** This lab is intentionally NOT a product command, backup/restore API, CI power-cut job, or authorization for deleting encrypted archives, SQLite, original signed proofs, user state or Core resources.

## Scope and explicit limits

The host-side `scripts/recovery_lab/vm_power_cut.py` can issue **one forced stop** against a specifically named, pinned-UUID **disposable ordinary-user libvirt `qemu:///session` guest**. It refuses system libvirt and root execution in destructive mode. It never touches the host's production daemon, normal XDG state or a running host Core.

The only currently permitted experimental checkpoints are:

| Case | Intended *guest-side* controlled point | Acceptance remains blocked on |
| --- | --- | --- |
| `T15-prepared-journal` | recovery journal durably prepared, no active generation replacement | rebooted journal reconciliation and unchanged Applied/LKG/Core |
| `T15-checked-candidate` | isolated historical candidate completed Core Check, before any activate | absence of mixed generation/rules and no unauthorized activation |
| `T23-sealed-archive-publish` | sealed encrypted archive publication/fsync boundary | intact original archive and independent read-only reauthentication after restart |
| `T23-signed-reclaim-proof` | signed inactive reclaim attestation/mirror publication/fsync boundary | retained original source audit and independently authenticated external signed history |

An experimental, operator-controlled **guest fixture must reach the real chosen fault boundary before generating a phase-ready marker**. This host tool does not create those markers, does not inject runtime faults itself and cannot authenticate a self-reported phase. Do not manufacture a marker manually and then count it as a passed test. Full SQLite/credential restore, active Core activation, second rollback and final metadata disposal remain unsupported.

A `virsh destroy` is similar to removing *virtual guest* power, not a certified electrical power failure of the host or underlying disk. Host page-cache and virtual block device semantics differ from physical loss. A forced-stop observation **does not** close T15/T23, which also requires after-boot invariant proofs and real-device power fault replay.

## Operator checklist and isolation requirements

1. Use a dedicated non-root host account, and confirm `virsh --connect qemu:///session` points to user-session libvirt only. Create a VM with a name beginning `ktui-t15t23-disposable-` from a *throwaway* disk image, with a recorded full 36-character lowercase UUID. Do not attach host production block devices, writable personal directories, live Karing/Karing TUI state, or network credentials. Keep an independently verified clean base image and the guest's version, filesystem, kernel and disk cache mode. The VM should have networking disconnected or isolated.
2. Before every test, clone the base image to a **new disposable VM**, choose a cryptographically random 16-byte nonce, create a host-owned `0700` scratch/witness directory, and mount only a dedicated synthetic guest-to-host phase channel to it with compatible UID mapping. Never share the host production SQLite state root.
3. Within the guest, use an independently instrumented fault fixture that writes exactly `KTUI_T15T23_LAB_READY_V1\ncase=<case>\nnonce=<nonce>\n` to `ready-<nonce>.txt` only after reaching the chosen journal/file-fsync checkpoint. The marker must be `0400` or `0600`, same owner as host operator, regular, single-linked and no symlink. Keep the separate phase trace, fixture commit, before-image and expected invariants outside the guest (owner-private; no secrets).
4. Run the host command **without** `--execute` first. It validates exact domain-name allowlist, full UUID, nonce, marker bytes, UID/mode/path and running VM state, and only reports `preview_only_no_vm_change`. It does not write files, destroy a guest or grant acceptance.
5. To force a virtual stop, deliberately set the exact `KTUI_LAB_VM_STOP_ACK` binding `EXECUTE:<domain>:<uuid>:<case>:<nonce>` and re-run with `--execute`. Root is refused. The tool fsyncs an owner-private exclusive `intent-<nonce>.json` before the VM stop, then uses `virsh --connect qemu:///session destroy --domain <domain>` with no shell, sudo, graceful shutdown or host reboot. It records `observation-<nonce>.json` only after independently seeing `shut off`. Both witness files are owner-only `0600`, non-overwriting and file+parent-directory fsynced.
6. If the tool fails after writing intent, **do not retry with the same nonce or assume the VM stayed on**. Inspect the VM and original witness files manually; no auto-resume, repair, cleanup or rollback is provided. The tool never removes a file or repairs an uncertain state.
7. Use a **separate explicit operator command** to restart only the disposable VM. Perform after-boot comparison: SQLite `integrity_check`/FK/schema and prepared journal, original Applied/LKG/selected-mode revision and hash, current generation/rule inode and SHA, original ciphertext HMAC and inventory, signed reclaim history and source-vs-detached distinction, Core Check/actual listening behavior without new active restore, absence of credentials/secret leaks and no orphan adoption. Record results independently; a successful pre-cut witness is *not* sufficient.
8. Record precise host and guest timestamps, version/architecture, pinned Core provenance, disk/fs mode, phase trace, original/after hashes, pass/fail invariant table, powered-on restart behavior and reproducible original VM image ID; redact all credentials. The audit cannot be certified from the host tool output alone.

## Example (host-side, non-production)

```sh
domain=ktui-t15t23-disposable-lab1
uuid="$(virsh --connect qemu:///session domuuid "$domain")"
case=T23-signed-reclaim-proof
nonce="$(openssl rand -hex 16)"
sandbox="$HOME/.local/state/karing-tui-v2/recovery-lab/run-$nonce"
install -d -m 0700 "$sandbox"

# The actual isolated guest fault fixture (not this script) must write
# "$sandbox/ready-$nonce.txt" with EXACT matching case+nonce at the fsync
# checkpoint. Missing/incorrect marker => the host tool refuses.
python3 scripts/recovery_lab/vm_power_cut.py \
  --domain "$domain" --uuid "$uuid" --case "$case" \
  --nonce "$nonce" --sandbox "$sandbox"

# Only after independent operator review of a truly disposable VM:
export KTUI_LAB_VM_STOP_ACK="EXECUTE:$domain:$uuid:$case:$nonce"
python3 scripts/recovery_lab/vm_power_cut.py \
  --domain "$domain" --uuid "$uuid" --case "$case" \
  --nonce "$nonce" --sandbox "$sandbox" --execute
unset KTUI_LAB_VM_STOP_ACK
```

**WARNING:** The `--execute` line causes an abrupt stop and loss of guest volatile work. Run it only against a newly cloned **throwaway VM with no user data**. It is not part of normal CI, not for physical hardware, and not for a user's running proxy.

## Automated safety regression (not a destructive test)

GitHub CI runs `python3 -m unittest discover -s scripts/recovery_lab -p 'test_*.py' -v`. A **mock** libvirt session checks preview nonmutating behavior, exact operator acknowledgement, domain+UUID pinning, private marker permissions/symlink/hardlink refusal, nonce replay denial and uncertain post-stop witness behavior. This CI uses no actual libvirt process or guest, and intentionally does **not** mark T15/T23 as passed.

## Release-stop conditions

Until physical/virtual crash replay and the full *post-restart invariants* are independently established, `PowerLossReplayVerified=false`, `RestoreSupported=false`, `RestoreReady=false`, and metadata cleanup remains disabled. This tool never generates a restore/deletion authorization. T15/T23, pending-orphan reconciliation, CN offline licensing, full Core rollback-of-rollback and 72h/7d/30d soak remain open.
