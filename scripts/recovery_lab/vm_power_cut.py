#!/usr/bin/env python3
"""Explicit operator-only virtual power-cut trigger for a disposable Linux guest.

This runs on the HOST, not inside karing-tui-v2. It never authorizes cleanup
or restore and does not claim that killing a virtual machine is physical
power-loss evidence. Ordinary go test/CI do not invoke the destructive mode.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

CASES = (
    "T15-prepared-journal",
    "T15-checked-candidate",
    "T23-sealed-archive-publish",
    "T23-signed-reclaim-proof",
)
DOMAIN_RE = re.compile(r"ktui-t15t23-disposable-[A-Za-z0-9-]{1,24}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
MAGIC = "KTUI_T15T23_LAB_READY_V1"
MAX_MARKER = 256


class LabRefusal(Exception):
    """No VM operation or successful audit receipt should be inferred."""


def marker_body(case: str, nonce: str) -> bytes:
    return (f"{MAGIC}\ncase={case}\nnonce={nonce}\n").encode("ascii")


def fail_if_bad_args(args: argparse.Namespace) -> None:
    if not DOMAIN_RE.fullmatch(args.domain) or not UUID_RE.fullmatch(args.uuid):
        raise LabRefusal("only named disposable session guests and exact UUIDs are allowed")
    if args.case not in CASES or not NONCE_RE.fullmatch(args.nonce):
        raise LabRefusal("unknown case or noncanonical 128-bit run nonce")
    path = Path(args.sandbox)
    state_root = os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))
    if not os.path.isabs(state_root) or ".." in Path(state_root).parts:
        raise LabRefusal("host XDG state root must be an absolute private path")
    expected = os.path.join(state_root, "karing-tui-v2", "recovery-lab",
                            "ktui-powercut-disposable-" + args.nonce)
    if (not path.is_absolute() or ".." in path.parts or
            str(path) != os.path.realpath(path) or str(path) != expected):
        raise LabRefusal("sandbox must be the dedicated per-nonce disposable recovery-lab directory")


def open_private_sandbox(path: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise LabRefusal("sandbox must be current-user-owned 0700 directory")
        return fd
    except BaseException:
        if "fd" in locals():
            os.close(fd)
        raise


def observe_ready(dfd: int, mfd: int, marker_name: str, expected: bytes) -> str:
    try:
        info = os.fstat(mfd)
        named = os.stat(marker_name, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or (
            stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
        ) or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > MAX_MARKER:
            raise LabRefusal("ready marker must be owner-only and single-linked")
        if (named.st_dev, named.st_ino, named.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise LabRefusal("ready marker was replaced")
        raw = os.pread(mfd, MAX_MARKER + 1, 0)
        if raw != expected or len(raw) != info.st_size:
            raise LabRefusal("phase/nonce marker mismatch")
        # Check the path->FD binding AFTER the entire read as well.
        later = os.stat(marker_name, dir_fd=dfd, follow_symlinks=False)
        if (later.st_dev, later.st_ino, later.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise LabRefusal("ready marker changed during validation")
        return hashlib.sha256(raw).hexdigest()
    except OSError as exc:
        raise LabRefusal("ready marker inaccessible or unsafe") from exc


def virsh_session(command: str, domain: str) -> str:
    """Never use system libvirt, shell interpolation, graceful shutdown or sudo."""
    if command not in ("domuuid", "domstate", "destroy"):
        raise LabRefusal("unsupported virtual machine operation")
    cmd = ["virsh", "--connect", "qemu:///session", command]
    if command == "destroy":
        cmd.append("--domain")
    cmd.append(domain)
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LabRefusal("the per-user libvirt command did not complete") from exc
    if run.returncode != 0:
        raise LabRefusal("per-user libvirt refused the operation")
    return run.stdout.strip()


def write_new_private_json(dfd: int, name: str, value: dict[str, object]) -> None:
    if not re.fullmatch(r"(intent|observation)-[0-9a-f]{32}\.json", name):
        raise LabRefusal("unsafe observation filename")
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > 4096:
        raise LabRefusal("observation exceeds fixed size limit")
    try:
        f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=dfd)
    except OSError as exc:
        raise LabRefusal("existing or unsafe intent/observation; never retry blindly") from exc
    try:
        with os.fdopen(f, "wb", closefd=True) as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.fsync(dfd)
    except OSError as exc:
        # Deliberately preserve an ambiguous partial file for manual review.
        raise LabRefusal("failed durable witness write; do not repair or retry") from exc


def run_case(args: argparse.Namespace, runner=virsh_session, effective_uid: int | None = None) -> dict[str, object]:
    fail_if_bad_args(args)
    uid = os.geteuid() if effective_uid is None else effective_uid
    if args.execute and uid == 0:
        raise LabRefusal("guest power-cut test must run as an ordinary host user")
    confirmation = f"EXECUTE:{args.domain}:{args.uuid}:{args.case}:{args.nonce}"
    if args.execute and os.environ.get("KTUI_LAB_VM_STOP_ACK") != confirmation:
        raise LabRefusal("missing exact per-domain UUID/case/nonce operator acknowledgement")

    with ExitStack() as stack:
        dfd = open_private_sandbox(args.sandbox)
        stack.callback(os.close, dfd)
        marker_name = "ready-" + args.nonce + ".txt"
        try:
            mfd = os.open(marker_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=dfd)
        except OSError as exc:
            raise LabRefusal("guest phase marker absent or unsafe") from exc
        stack.callback(os.close, mfd)
        marker_hash = observe_ready(dfd, mfd, marker_name, marker_body(args.case, args.nonce))
        if runner("domuuid", args.domain) != args.uuid:
            raise LabRefusal("guest UUID does not match the explicitly pinned disposable VM")
        if runner("domstate", args.domain) != "running":
            raise LabRefusal("guest must be running at the matching phase")
        base = {
            "schema_version": 1,
            "case": args.case,
            "nonce": args.nonce,
            "domain": args.domain,
            "domain_uuid": args.uuid,
            "marker_sha256": marker_hash,
            "guest_boot_verified": False,
            "post_reboot_consistency_verified": False,
            "physical_power_loss_verified": False,
            "restore_authorized": False,
            "metadata_deletion_authorized": False,
        }
        if not args.execute:
            return {**base, "status": "preview_only_no_vm_change"}
        # Persist a non-overwriting witness BEFORE a potentially destructive
        # VM stop. An exception after intent publication leaves an ambiguous
        # state requiring manual investigation; it never triggers auto-retry.
        intent = "intent-" + args.nonce + ".json"
        observed = "observation-" + args.nonce + ".json"
        for name in (intent, observed):
            try:
                os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise LabRefusal("nonce has already been used; review prior witnesses")
        write_new_private_json(dfd, intent, {
            **base, "status": "intent_before_forced_virtual_stop",
            "time_utc": datetime.now(timezone.utc).isoformat(),
        })
        if observe_ready(dfd, mfd, marker_name, marker_body(args.case, args.nonce)) != marker_hash:
            raise LabRefusal("guest marker drifted after durable intent")
        if runner("domuuid", args.domain) != args.uuid or runner("domstate", args.domain) != "running":
            raise LabRefusal("guest changed before forced stop; intent retained")
        runner("destroy", args.domain)
        if runner("domstate", args.domain) != "shut off":
            raise LabRefusal("guest stop not independently observed; intent retained")
        result = {
            **base,
            "status": "virtual_guest_forced_off_observed",
            "time_utc": datetime.now(timezone.utc).isoformat(),
        }
        write_new_private_json(dfd, observed, result)
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True, help="ktui-t15t23-disposable-* guest, qemu:///session only")
    parser.add_argument("--uuid", required=True, help="exact lowercase libvirt UUID")
    parser.add_argument("--case", required=True, choices=CASES)
    parser.add_argument("--nonce", required=True, help="unique lowercase 32-hex run nonce")
    parser.add_argument("--sandbox", required=True, help="existing owned 0700 host witness directory")
    parser.add_argument("--execute", action="store_true", help="dangerous explicit forced virtual stop")
    args = parser.parse_args(argv)
    try:
        result = run_case(args)
    except LabRefusal as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
