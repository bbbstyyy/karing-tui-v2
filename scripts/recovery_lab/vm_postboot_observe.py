#!/usr/bin/env python3
"""Read-only libvirt post-start observer for an ALREADY manually restarted disposable VM.

Never boots or stops a VM, connects to system libvirt, or grants guest-reboot,
electrical power-loss, Core, archive, restore or cleanup authorization. The
default preview does not write anything. Recording needs a separate exact ACK.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
import sys

import vm_power_cut as vm

SHA = re.compile(r"[0-9a-f]{64}\Z")
UTC = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?\+00:00\Z")
BASELINE_VERSION = 12  # guest_reboot_audit.py witness, NOT production SQLite
MAX_BASELINE = 16 << 10
MAX_RECEIPT = 4096


def refuse(message: str):
    raise vm.LabRefusal(message)


def read_private_json(dfd: int, name: str, maximum: int) -> tuple[dict, str]:
    if not re.fullmatch(
            r"(baseline|intent|observation)-[0-9a-f]{32}\.json", name):
        refuse("unapproved witness name")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            before = os.fstat(fd)
            named = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)
            if (not stat.S_ISREG(before.st_mode) or
                    before.st_uid != os.geteuid() or before.st_nlink != 1 or
                    stat.S_IMODE(before.st_mode) not in (0o400, 0o600) or
                    not 0 < before.st_size <= maximum or
                    identity(before) != identity(named)):
                refuse("private witness is not an immutable owner-only regular file")
            raw = os.pread(fd, maximum + 1, 0)
            after = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if len(raw) != before.st_size or identity(after) != identity(before):
                refuse("private witness changed while being read")

            def unique(fields):
                result = dict(fields)
                if len(result) != len(fields):
                    refuse("duplicate private witness JSON keys")
                return result
            try:
                data = json.loads(
                    raw, object_pairs_hook=unique,
                    parse_constant=lambda _: refuse("invalid JSON constant"))
            except (UnicodeError, ValueError) as exc:
                raise vm.LabRefusal("invalid private JSON witness") from exc
            if not isinstance(data, dict):
                refuse("private witness must be a JSON object")
            return data, hashlib.sha256(raw).hexdigest()
        finally:
            os.close(fd)
    except OSError as exc:
        raise vm.LabRefusal("missing or unsafe private witness") from exc


def timestamp(raw: object) -> datetime:
    if not isinstance(raw, str) or not UTC.fullmatch(raw):
        refuse("noncanonical host UTC receipt timestamp")
    try:
        return datetime.fromisoformat(raw)
    except ValueError as exc:
        raise vm.LabRefusal("invalid host receipt clock") from exc


def inspect_chain(dfd: int, args: argparse.Namespace) -> tuple[str, str, str, datetime]:
    """Bind pre-cut guest baseline SHA and both real host-writer receipts."""
    marker_name = "ready-" + args.nonce + ".txt"
    try:
        fd = os.open(marker_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=dfd)
    except OSError as exc:
        raise vm.LabRefusal("missing or unsafe guest phase marker") from exc
    try:
        marker_sha = vm.observe_ready(
            dfd, fd, marker_name, vm.marker_body(args.case, args.nonce))
    finally:
        os.close(fd)

    baseline, baseline_sha = read_private_json(
        dfd, "baseline-" + args.nonce + ".json", MAX_BASELINE)
    if (baseline_sha != args.baseline_sha256 or
            set(baseline) != {
                "format", "case", "nonce", "domain", "domain_uuid",
                "phase_marker_sha256", "state",
            } or type(baseline["format"]) is not int or
            baseline["format"] != BASELINE_VERSION or
            not isinstance(baseline["state"], dict) or
            (baseline["case"], baseline["nonce"], baseline["domain"],
             baseline["domain_uuid"], baseline["phase_marker_sha256"]) !=
            (args.case, args.nonce, args.domain, args.uuid, marker_sha)):
        refuse("guest baseline is not the externally pinned v12 pre-cut witness")

    fixed = {
        "schema_version": 1,
        "case": args.case, "nonce": args.nonce,
        "domain": args.domain, "domain_uuid": args.uuid,
        "marker_sha256": marker_sha,
        "guest_boot_verified": False,
        "post_reboot_consistency_verified": False,
        "physical_power_loss_verified": False,
        "restore_authorized": False,
        "metadata_deletion_authorized": False,
    }
    def receipt(kind: str, status: str):
        doc, digest = read_private_json(
            dfd, kind + "-" + args.nonce + ".json", MAX_RECEIPT)
        if (set(doc) != set(fixed) | {"status", "time_utc"} or
                doc.get("status") != status or
                any(type(doc.get(k)) is not type(v) or doc.get(k) != v
                    for k, v in fixed.items())):
            refuse("host stop receipt does not match the pinned guest identity")
        return digest, timestamp(doc["time_utc"])

    intent_sha, intent_time = receipt("intent", "intent_before_forced_virtual_stop")
    observation_sha, observation_time = receipt(
        "observation", "virtual_guest_forced_off_observed")
    if observation_time < intent_time:
        refuse("observed host stop is earlier than its durable intent")
    return marker_sha, intent_sha, observation_sha, observation_time


def run_case(args: argparse.Namespace, runner=vm.virsh_session,
             effective_uid: int | None = None) -> dict[str, object]:
    vm.fail_if_bad_args(args)
    if not SHA.fullmatch(args.baseline_sha256 or ""):
        refuse("missing independently pinned baseline SHA-256")
    uid = os.geteuid() if effective_uid is None else effective_uid
    if args.record and uid == 0:
        refuse("post-start observation must use an unprivileged host user")
    confirmation = (f"OBSERVE:{args.domain}:{args.uuid}:{args.case}:"
                    f"{args.nonce}:{args.baseline_sha256}")
    if args.record and os.environ.get("KTUI_LAB_VM_POSTBOOT_ACK") != confirmation:
        refuse("missing exact post-start manual observation acknowledgement")

    with ExitStack() as stack:
        dfd = vm.open_private_sandbox(args.sandbox)
        stack.callback(os.close, dfd)
        expected = inspect_chain(dfd, args)
        output_name = "poststart-" + args.nonce + ".json"
        try:
            os.stat(output_name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise vm.LabRefusal("cannot check post-start receipt identity") from exc
        else:
            refuse("post-start receipt already exists; do not overwrite or repeat")
        if runner("domuuid", args.domain) != args.uuid:
            refuse("running guest does not match pinned disposable UUID")
        if runner("domstate", args.domain) != "running":
            refuse("the same disposable VM is not observed running")
        if inspect_chain(dfd, args) != expected:
            refuse("pre-cut witness changed during libvirt observation")

        marker_sha, intent_sha, observation_sha, observation_time = expected
        observed = datetime.now(timezone.utc)
        if observed < observation_time:
            refuse("host clock places running observation before virtual stop")
        base = {
            "schema_version": 1,
            "case": args.case, "nonce": args.nonce,
            "domain": args.domain, "domain_uuid": args.uuid,
            "marker_sha256": marker_sha,
            "baseline_sha256": args.baseline_sha256,
            "intent_sha256": intent_sha,
            "observation_sha256": observation_sha,
            "guest_boot_verified": False,
            "post_reboot_consistency_verified": False,
            "physical_power_loss_verified": False,
            "core_health_verified": False,
            "archive_hmac_verified": False,
            "restore_authorized": False,
            "metadata_deletion_authorized": False,
        }
        if not args.record:
            return {**base, "status": "preview_only_no_receipt"}
        # Second pinned VM check, but NEVER invoke start, destroy or shutdown.
        if runner("domuuid", args.domain) != args.uuid or (
                runner("domstate", args.domain) != "running"):
            refuse("disposable VM state changed before receipt publication")
        if inspect_chain(dfd, args) != expected:
            refuse("host witnesses changed before post-start receipt publication")
        receipt = {
            **base, "status": "virtual_guest_running_observed_after_forced_off",
            "time_utc": observed.isoformat(),
        }
        vm.write_new_private_json(dfd, output_name, receipt)
        return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--uuid", required=True)
    parser.add_argument("--case", required=True, choices=vm.CASES)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--record", action="store_true",
                        help="write a one-time non-authorizing host witness; never start/stop VM")
    args = parser.parse_args(argv)
    try:
        report = run_case(args)
    except (vm.LabRefusal, OSError, ValueError) as exc:
        print("REFUSED: disposable VM post-start observation is not trustworthy",
              file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
