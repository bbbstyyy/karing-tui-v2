# T15/T23 disposable guest — SQLite before/after replay subset

**Status: lab-only. This check cannot certify reboot, electrical power loss, Core health, restored credentials, full archive HMAC or metadata cleanup.**

This is an optional follow-up to the [ADR 0128 VM forced-stop runbook](t15-t23-virtual-powercut-lab.md). Run `guest_reboot_audit.py` **inside an independently provisioned throwaway guest**, under its ordinary non-root operator user. Never point the tools at a normal user's real XDG state or disk.

## Required laboratory setup

1. Use a disposable `ktui-t15t23-disposable-*` user-session VM with an explicitly recorded lowercase UUID and exactly one of the four ADR 0128 checkpoint names. The guest's own `$XDG_STATE_HOME/karing-tui-v2/state.db` must be a known test database, not imported live personal data.
2. Mount a separate host-controlled test-witness channel at the guest's `$XDG_STATE_HOME/karing-tui-v2/recovery-lab/ktui-powercut-disposable-<nonce>`. Owner and permissions must support ordinary-user 0700 directories and non-symlinked 0600 files. Do not mount the host's production XDG state. A host/guest copy would require separate independent identity binding; this script assumes a deliberate, isolated test channel.
3. Stop test guest daemon writers before the **before** snapshot. The script cannot enforce global exclusion of other SQLite writers; it uses only read-only queries, pinned private file identity and a fixed subset of domain checks. Any competing writer makes the result untrustworthy.
4. Independently capture the original expected Applied/LKG, selection, desired Core state and rule/file SHA/manifest outside this tool. Run the earlier real *guest fixture* to reach the selected fsync/checkpoint; the host forced-stop tool neither creates the checkpoint nor authenticates it.
5. Print the baseline SHA before stopping the guest and preserve it **outside the guest** as an operator-pinned input. A local SHA is not an HMAC or proof against a malicious operator. Never fabricate a baseline to make an incident look consistent.

## Guest command sequence

Run `--mode capture` **before** the fault, after explicitly setting the nonce and matching disposable VM identity, from a trusted checkout of this repository:

```sh
export XDG_STATE_HOME="$HOME/.local/state"
domain=ktui-t15t23-disposable-lab1
uuid=01234567-89ab-cdef-0123-456789abcdef
case=T15-prepared-journal
nonce=0123456789abcdef0123456789abcdef
witness="$XDG_STATE_HOME/karing-tui-v2/recovery-lab/ktui-powercut-disposable-$nonce"

# The independently instrumented test environment must already have created
# this owner-private witness directory and the test SQLite state.db.
export KTUI_LAB_GUEST_AUDIT_ACK="GUEST_AUDIT:$domain:$uuid:$case:$nonce"
python3 scripts/recovery_lab/guest_reboot_audit.py \
  --mode capture --domain "$domain" --uuid "$uuid" \
  --case "$case" --nonce "$nonce" --witness "$witness"

# Store the printed baseline_sha256 outside this guest.
```

Next, independently execute the ADR 0128 host-side **disposable-only** VM stop at the actual checkpoint, using the same domain/UUID/case/nonce and a separate exact manual acknowledgement. Do not trigger a real host reboot or stop any user production instance. Then manually restart **only the disposable VM** and keep the test application's daemon/Core stopped until the read-only snapshot audit finishes.

After restart, inside that same guest:

```sh
# The value must match the separately stored sha256 returned before the cut;
# never derive it from the potentially compromised current witness file.
baseline_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
python3 scripts/recovery_lab/guest_reboot_audit.py \
  --mode verify --domain "$domain" --uuid "$uuid" \
  --case "$case" --nonce "$nonce" --witness "$witness" \
  --baseline-sha256 "$baseline_sha256"
unset KTUI_LAB_GUEST_AUDIT_ACK
```

Replace the UUID, nonce and SHA examples with fresh, independently recorded values. Reuse of a nonce and overwrite of an existing baseline are forbidden. A missing/changed host stop observation or invalid, active/recovery-required SQLite state produces refusal, not a repaired database.

## What is actually checked

The checker uses a read-only SQLite URI, never `immutable=1`, requires v18 migration sequence, SQLite `integrity_check`, foreign-key check, daemon/selection singleton, valid Core desired mode and routing mode, at most one active apply, and at most one prepared *inert* restore record. It cryptographically checks the stored SHA-256 against actual SQLite BLOBs for the Applied/LKG config, manifest and source-map fields, and compares redacted version/IDs/SHAs/selection state against the original baseline.

Only the SQLite **subset** can match. The tool does not inspect the entire schema catalog, unreferenced records, rule content-addressed inode leases, encrypted backup HMAC, historical signed archive evidence, live network observations or rollback-of-rollback; nor can it independently prove a reboot happened. Even a matching result sets all of `guest_reboot_verified`, `physical_power_loss_verified`, `core_health_verified`, `archive_hmac_verified`, `restore_authorized` and `metadata_deletion_authorized` to **false**.

No output closes T15/T23. The official release gate additionally requires operator-observed full restart traces, immutable original-source and detached-history authentication, Core/routing health and double rollback, actual real-device power-fault replay, reviewed retention/deletion policy, and the long-duration stability matrix.

## CI safety boundary

CI invokes only `python3 -m unittest discover -s scripts/recovery_lab -p 'test_*.py' -v`, with synthetic ephemeral SQLite records and fake host-stop JSON. It **never** runs a VM stop, changes the developer's personal database or generates a real power-loss success receipt.
