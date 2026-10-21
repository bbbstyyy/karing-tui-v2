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

## ADR 0132: compare an independently reconciled prepared fixture (optional, read-only)

The version-2 baseline format **is not compatible** with prior v1 witness files; never overwrite an existing baseline or re-pin its SHA from the guest after the event. Use a fresh nonce/fixture instead. For an original `T15-prepared-journal` snapshot, ordinary `--mode verify` **must still refuse** both the unreconciled pending journal and any post-reconciliation state different from its pre-cut baseline.

The additional `--mode reconcile-verify` is a *separate*, narrower diagnostic. Only after an independently reviewed, explicit test-only `storage.RecoverInterrupted` against the disposable VM's own **isolated experimental** v18 Store (never a user's actual DB), run the same Python auditor with the original externally pinned baseline, `--mode reconcile-verify`, the original nonce/domain/UUID/case/witness values and matching `KTUI_LAB_GUEST_AUDIT_ACK`. It reads only; it does **not** perform recovery, and no production command to conduct guest recovery is provided.

The mode checks that a single original prepared candidate became an inactive interrupted attempt with exactly the standard recovery marker, while Applied/LKG and other audited SQLite fields remain identical. Changed candidate data *even with a recalculated matching digest*, any changed selector/revision, unexpected phase, forged stop witness or extra journal row refuses. Success is only `prepared_journal_sqlite_subset_manual_review_only`, not proof that any VM stopped or booted, Core was healthy, archival signatures were checked, or restoration and deletion are authorized. Preserve before/after disk and independent traces for manual review.

## ADR 0133: postactivation and failed rollback are NOT prepared-only safe replays

If the pinned pre-cut guest journal phase was `activating`, `verifying` or `rolling_back`, the Core may have changed before interruption. The narrow ADR 0132 `reconcile-verify` is **ineligible**. When an explicitly isolated test harness calls `RecoverInterrupted`, it marks the interrupted row and sets `RecoveryRequired=true`; subsequent calls and process reopen must leave this manual hold in place until separate active-Core reconciliation has independent evidence. A terminal `FailRollback` retains the hold even without an active journal. Do not clear `RecoveryRequired` merely because SQLite opened or LKG bytes still match. No automatic retry, deletion, public restoration or reactivation is allowed. The CI tests for this only use disposable Go v18 databases and fake host-stop JSON, never an actual guest power interruption.

## ADR 0134: version-3 complete bounded archived-history pinning

Guest `capture` now includes `apply_history_ledger_sha256` for **every** retained `apply_history` row, not only the latest. All reads remain WAL-aware `mode=ro`, limited to **512 archived attempts**, with bounded error/timestamp fields. The unprinted archived error strings contribute to the ordered SHA digest; no extra authority is granted. Both `--mode verify` and `--mode reconcile-verify` require an identical externally pinned history ledger. An unchanged current Applied/LKG and newest archived record does **not** prove safety if an older archived row changed.

**Breaking witness contract:** baseline format v3 replaces v2 (the application SQLite schema is still v18). Never overwrite or attempt to reinterpret an old v2 baseline; start a fresh disposable guest experiment with a new random nonce and independently store its SHA away from the guest. >512 archived records or malformed fields cause a refusal/manual hold. The ledger is not a signed archive, Core health report, VM power/reboot attestation or retention deletion authorization.

## ADR 0135: independent inert restore journal pinning (guest v4)

The guest witness **v4** format now includes `inert_restore_record_count` and `inert_restore_ledger_sha256` for every retained `inert_restore_preparations` record (at most 32, otherwise refuse). Both the original strict comparison and prepared-only `reconcile-verify` require exactly the same inert-record ledger. A single `prepared` record whose candidate scope/archive digest/inventory digest or baseline fence has changed is **not** equivalent to the pre-cut record, even when the prepared count remains one. An explicit `AbandonInertRestoreRecord` changes the baseline: the old externally pinned v4 SHA is not valid for that new state.

For a new manual experiment, **do not overwrite or silently reinterpret v3 or earlier witness files**; provision a fresh disposable VM/nonce and independently save the new baseline SHA outside the guest. A read-only digest is not authorization to locate/import/decrypt any archive, clear a recovery hold, restart Core, dispose of original source metadata or claim T15/T23. All six safety flags remain false even if the observed SQLite subset matches.

## ADR 0136: reject rehashed noncanonical inert fences (guest witness v5)

Guest `capture` and both verification modes now require that every `inert_restore_preparations.baseline_json` field match the **canonical Go `InertRestoreFence`** shape and compact JSON encoding, including all 16 exported fields and allowed enum/digest/numeric domains. Rehashing the JSON after changing its order, fields, whitespace or values does not make an invalid Go Store record trustworthy. If the before-cut guest fixture is malformed, `capture` refuses without producing a new baseline. Even a valid Go fence remains only a non-authorizing historical observation: its currentness, candidate encryption/HMAC, VM/Core state and actual recovery must be independently established.

The guest baseline format is now **v5**; do not overwrite or reinterpret v4/older witnesses. Always provision a fresh isolated test VM and random nonce for a new experiment. No power interruption, Core activation, restoration or deletion is executed by the auditing workflow.

## ADR 0137: audit every still-retained Go v18 generation (guest baseline v6)

For a **new** disposable guest experiment, `capture` now digests all currently retained generations, with a hard 128-row cap and strict JSON/SHA pairs for config, manifest and source-map. A generation outside Applied/LKG or the latest journal is still included. Any changed old config body **even when its stored SHA is recalculated**, metadata, revision, timestamp or record count must fail the subsequent `verify` or narrow `reconcile-verify`. An oversize or malformed candidate refuses at capture time; the tool remains read-only, does not repair SQLite and never recovers missing generations already pruned.

**Witness format v6 is incompatible with v5 and all older versions.** Preserve old independent SHA evidence; never overwrite a pinned guest baseline or recapture to bless unexpected changes. Do not report actual VM stop/reboot, physical power-loss durability, encrypted archive HMAC, live Core health, restoration, credentials import or metadata deletion from this result.

## ADR 0138: bounded historical routing/DNS declaration evidence (guest v7)

All read-only guest captures now include the complete retained `declaration_revisions` chain with a strict 128-entry cap, JSON/SHA verification, parent continuity and consistency with the single current declaration pointer. A *historic* declaration is not exempt just because current Applied/LKG and the latest head remain identical; a matching recalculated SHA on modified JSON invalidates an independently pinned guest baseline. The report contains only counts, current revision and a digest, never declaration payloads.

**Witness v7 is incompatible with prior v6** (application SQLite remains v18). Start a new owner-private disposable guest/nonce and independently save its SHA. Never overwrite an earlier baseline or infer real VM reboot, physical power-loss durability, core routing validity, resource-file closure, archive HMAC, credential restoration or deletion approval from this evidence.

## ADR 0139: previous/current profile snapshot evidence (guest baseline v8)

Only a new disposable ordinary-user guest may capture the v8 read-only witness. The audit inspects v18 `profile_state`, exactly retained previous/current snapshot metadata and all snapshot-node JSON+SHA pairs under the same WAL-aware read transaction. It pins only row counts and an ordered digest: IDs, node parameters, subscription URLs or timestamps are not printed. The auditor refuses orphan snapshots, broken ownership/pointers, invalid JSON/ordinal/digest or guest-only caps (64 profile states, 128 snapshots, 8192 nodes, 48 MiB cumulative payload). A changed *previous* snapshot with a simultaneously recalculated stored SHA must invalidate the independently pinned pre-stop SHA even when the current profile and Applied/LKG are unchanged.

**Witness v8 is not compatible with v7 or older**. Do not rewrite, overwrite, or "upgrade" prior baselines or reuse a nonce: provision fresh private guest state and preserve the external SHA. This does not audit the separate `profile_sources` and `profile_node_overlays` tables or authenticate remote subscription bytes. It does not prove a real VM stop/reboot, Core connectivity, electrical durability, archive HMAC or restoration, and does not authorize cleanup.

## ADR 0140: bounded node user override evidence (guest witness v9)

For a fresh isolated ordinary-user disposable VM, the **read-only WAL-aware** SQLite observation now checks every `profile_node_overlays` row (including previously removed node IDs) for positive revision, bool flags, Go-compatible alias/sort rank/IDs and bounded offset-aware timestamp. The complete sorted-row digest and count enter the private witness; no alias, subscription secret, profile ID or node ID is output in the report. Over 2,048 total rows refuses before capturing a baseline. The auditor rejects changed dormant-node overrides even when the active profile snapshot, Applied/LKG and source-map are unchanged, and preserves the same digest through the narrow prepared-only recovery comparison.

**Witness v9 is incompatible with v8 and older versions.** Preserve all earlier externally SHA-pinned evidence separately; do not overwrite it, reuse a nonce or recapture after unexpected drift. The new ledger is not remote subscription authentication, physical restart/power-loss proof, archive HMAC, Core health, restoration or metadata-deletion authorization. Profile source fetch/lease/usage state remains unverified by this particular ledger.

## ADR 0141: source URL, update lease and usage evidence (guest witness v10)

For a **new** isolated owner-private ordinary-user guest, capture a v10 witness only while the v18 SQLite database is under a single WAL-aware read-only transaction. It includes a bounded, sorted digest of **every persisted `profile_sources` field** (max 64 source rows): the private raw URL/path, filter/fetch mode, update cadence, cache validators, timestamps, usage and pending source-update lease. It checks syntax, allowed values and null pairing but **does not fetch subscriptions**. No URL, token, profile ID, HTTP metadata or error message appears in the report. A source may legitimately lack an accepted snapshot. Drift in either a source without snapshot or its previously stable update metadata invalidates the original externally pinned SHA.

A live-shaped update lease may be *observed*, but subsequent `RecoverInterruptedProfileUpdates` clears it with independent writes. Do **not** call this a supported T15 prepared-apply reconciliation: unlike the narrow apply-journal change, source-lease recovery must trigger a separate manual hold and new independent assessment. Baseline **v10 is incompatible with v9 or older**; never overwrite/reuse old nonce, baseline or external pinned digest. No real VM cut/reboot, Core traffic check, source authenticity, archive HMAC, restoration or cleanup permission is provided by this guest audit.

## ADR 0142 — host-phase stop-chain binding (guest witness v11)

When provisioning a **new isolated disposable ordinary-user VM**, use a genuine instrumented guest checkpoint to write `ready-<nonce>.txt` **before** capturing v11. The capture binds the exact marker bytes and SHA to the pre-stop SQLite baseline, whose SHA must be pinned *outside the guest*. The separate non-root host `vm_power_cut.py --execute` must then produce the original owner-private **intent-before-forced-stop** and **shut-off-observed** records for the same domain/UUID/case/nonce. If either record is missing, symlinked, hardlinked, lax-permissioned, incomplete, forged, reversed in time, or its marker digest differs from the pre-cut baseline, **both verification modes refuse** even when SQLite v18 is unchanged. Do not manufacture or "repair" a missing intent file and do not recapture to cover up drift.

The auditor returns `host_stop_chain_checked=true` only for strict local record/schema/marker continuity, not as a VM restart, clock, electrical loss, network/Core, archive HMAC, rollback or credential proof. The host operator may alter these records; all post-restart invariant evidence must remain independently reviewed. This step performs **no VM action, data modification, restoration, cleanup or release approval**. The v11 baseline is incompatible with v10/older; use a new unique nonce/witness and preserve prior copies, rather than upgrading in place.
