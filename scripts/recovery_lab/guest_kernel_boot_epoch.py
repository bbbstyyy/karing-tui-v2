#!/usr/bin/env python3
"""Read-only Linux boot-identity continuity probe for disposable T15/T23 guests.

This script reads the REAL /proc/sys/kernel/random/boot_id; it does not boot,
stop, repair, restore or delete anything. The before/after local kernel IDs
are not independently authenticated hypervisor reboot or power-loss proof.
Only a distinct guest + external evidence can satisfy the full release gate.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import re
import sys

import guest_reboot_audit as guest
import vm_power_cut as vm

SCHEMA = 1  # separate boot-epoch evidence, NOT a production SQLite migration
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
EPOCH_RE = re.compile(r"boot-epoch-[0-9a-f]{32}\.json\Z")
BOOT_FLAGS = {
    "guest_reboot_verified": False,
    "physical_power_loss_verified": False,
    "core_health_verified": False,
    "archive_hmac_verified": False,
    "restore_authorized": False,
    "metadata_deletion_authorized": False,
}


def refuse(message: str):
    raise guest.AuditRefusal(message)


def read_kernel_boot_id() -> str:
    """Production reader is always the Linux procfs boot ID, never CLI input."""
    try:
        fd = os.open(
            BOOT_ID_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 80)
        finally:
            os.close(fd)
        # Procfs reports 36 canonical ASCII bytes, optionally newline.
        if len(raw) == 37 and raw.endswith(b"\n"):
            raw = raw[:-1]
        value = raw.decode("ascii")
    except (OSError, UnicodeError) as exc:
        raise guest.AuditRefusal("Linux kernel boot identity unavailable") from exc
    if not vm.UUID_RE.fullmatch(value) or value == "00000000-0000-0000-0000-000000000000":
        refuse("invalid Linux kernel boot identity")
    return value


def valid_boot_id(value: object) -> bool:
    return (isinstance(value, str) and vm.UUID_RE.fullmatch(value) is not None and
            value != "00000000-0000-0000-0000-000000000000")


def pinned_baseline(dfd: int, args: argparse.Namespace) -> str:
    if not guest.SHA.fullmatch(args.baseline_sha256 or ""):
        refuse("missing independently stored pre-stop guest baseline SHA")
    marker_sha = guest.private_phase_marker_at(dfd, args)
    doc, actual_sha = guest.private_json_at(
        dfd, "baseline-" + args.nonce + ".json")
    required = {
        "format", "case", "nonce", "domain", "domain_uuid",
        "phase_marker_sha256", "state",
    }
    if (actual_sha != args.baseline_sha256 or set(doc) != required or
            type(doc.get("format")) is not int or
            doc["format"] != guest.VERSION or
            not isinstance(doc.get("state"), dict) or
            (doc.get("case"), doc.get("nonce"), doc.get("domain"),
             doc.get("domain_uuid"), doc.get("phase_marker_sha256")) !=
            (args.case, args.nonce, args.domain, args.uuid, marker_sha)):
        refuse("pre-stop v12 guest baseline is not externally pinned")
    return marker_sha


def no_prior_host_stop(dfd: int, nonce: str) -> None:
    # A first-time capture must be done BEFORE a stop attempt, not recreated
    # after an operator lost their original kernel pre-stop evidence.
    for kind in ("intent", "observation", "poststart"):
        name = kind + "-" + nonce + ".json"
        try:
            os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise guest.AuditRefusal("cannot inspect previous host stop evidence") from exc
        refuse("kernel identity baseline cannot be captured after host stop")


def epoch_doc(args: argparse.Namespace, marker_sha: str, old_boot: str) -> dict:
    return {
        "schema_version": SCHEMA,
        "status": "guest_kernel_boot_identity_before_virtual_stop",
        "case": args.case,
        "nonce": args.nonce,
        "domain": args.domain,
        "domain_uuid": args.uuid,
        "baseline_sha256": args.baseline_sha256,
        "phase_marker_sha256": marker_sha,
        "kernel_boot_id": old_boot,
        **BOOT_FLAGS,
    }


def write_epoch(dfd: int, nonce: str, record: dict) -> str:
    name = "boot-epoch-" + nonce + ".json"
    if not EPOCH_RE.fullmatch(name):
        refuse("invalid private kernel boot witness name")
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > 4096:
        refuse("kernel boot witness exceeds guest-only bound")
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(fd)
        os.fsync(dfd)
    finally:
        os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def inspect(args: argparse.Namespace) -> dict:
    witness, _ = guest.strict_args(args)
    with ExitStack() as stack:
        dfd = guest.private_fd(witness, 0, directory=True)
        stack.callback(os.close, dfd)
        marker_sha = pinned_baseline(dfd, args)
        before_or_current_boot = read_kernel_boot_id()
        if not valid_boot_id(before_or_current_boot):
            refuse("noncanonical guest kernel boot identity")
        if args.mode == "capture":
            no_prior_host_stop(dfd, args.nonce)
            doc = epoch_doc(args, marker_sha, before_or_current_boot)
            raw_sha = write_epoch(dfd, args.nonce, doc)
            if (read_kernel_boot_id() != before_or_current_boot or
                    pinned_baseline(dfd, args) != marker_sha or
                    not guest.file_identity(dfd, witness)):
                refuse("boot identity or pre-stop witness changed during capture")
            return {
                "status": "guest_kernel_boot_identity_pinned_no_reboot_claim",
                "boot_epoch_sha256": raw_sha,
                "kernel_boot_identity_changed_observed": False,
                **BOOT_FLAGS,
            }

        if not guest.SHA.fullmatch(args.boot_epoch_sha256 or ""):
            refuse("missing independently pinned pre-stop kernel witness SHA")
        epoch_name = "boot-epoch-" + args.nonce + ".json"
        record, original_sha = guest.private_json_at(
            dfd, epoch_name, maximum=4096)
        if original_sha != args.boot_epoch_sha256:
            refuse("pre-stop kernel witness no longer matches external SHA")
        old_boot = record.get("kernel_boot_id")
        if (not valid_boot_id(old_boot) or
                record != epoch_doc(args, marker_sha, old_boot) or
                before_or_current_boot == old_boot):
            refuse("kernel boot identity did not change or witness was modified")

        host_chain = guest.host_stop_chain_at(dfd, args, marker_sha)
        post_sha = guest.host_poststart_at(
            dfd, args, marker_sha, args.baseline_sha256, host_chain)
        # Read the kernel and independently pinned files again, to fail closed
        # on a concurrent process/namespace or witness replacement.
        after_doc, after_sha = guest.private_json_at(
            dfd, epoch_name, maximum=4096)
        if (read_kernel_boot_id() != before_or_current_boot or
                after_sha != original_sha or after_doc != record or
                pinned_baseline(dfd, args) != marker_sha or
                guest.host_stop_chain_at(dfd, args, marker_sha) != host_chain or
                guest.host_poststart_at(
                    dfd, args, marker_sha, args.baseline_sha256, host_chain) != post_sha or
                not guest.file_identity(dfd, witness)):
            refuse("kernel or original host/guest witness changed during observation")
        return {
            "status": "guest_kernel_boot_identity_changed_manual_review_only",
            "kernel_boot_identity_changed_observed": True,
            "host_running_observation_checked": True,
            "sqlite_subset_checked": False,
            **BOOT_FLAGS,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("capture", "verify"))
    parser.add_argument("--case", required=True, choices=vm.CASES)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--uuid", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--boot-epoch-sha256",
                        help="original externally stored SHA from --mode capture")
    args = parser.parse_args(argv)
    try:
        report = inspect(args)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (guest.AuditRefusal, vm.LabRefusal, OSError, ValueError):
        # Never disclose private paths, environment, journal contents or boot ID.
        print("REFUSED: disposable guest Linux boot identity check is not trustworthy",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
