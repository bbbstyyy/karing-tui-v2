#!/usr/bin/env python3
"""T24 partial: configured approved Core, but NO generation, in native airgap.

The real Daemon must never spawn a Core without a committed generation.
An explicit invalid start may persist running *intent*; this experiment
always sends an explicit stop to restore stopped intent before restart.
Does not apply any config, route packets, use CN resources or certify release.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

import t24_airgap_bootstrap as boot

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CORE_PORTS = (2080, 2081, 2082, 3057)
MAX_CORE_BYTES = 96 << 20


def require(condition, message):
    boot.require(condition, message)


def hash_pinned_core(path: Path, expected: str, require_root_owner=True) -> str:
    require(bool(HEX64.fullmatch(expected)), "invalid pinned Core checksum")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise RuntimeError("Core file cannot be opened securely") from exc
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                (before.st_mode & 0o111) != 0 and
                (before.st_mode & 0o022) == 0 and
                0 < before.st_size <= MAX_CORE_BYTES,
                "staged Core is not one bounded private executable")
        if require_root_owner:
            require(before.st_uid == 0, "staged Core must be root-owned on host")
        digest = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as stream:
            while True:
                chunk = stream.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
        after = os.fstat(fd)
        props = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode,
                           s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
        require(props(before) == props(after) and
                digest.hexdigest() == expected,
                "staged Core hash or identity mismatch")
        return digest.hexdigest()
    finally:
        os.close(fd)


def fresh_env(root: Path, core: str) -> dict[str, str]:
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(root),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_STATE_HOME": str(root / "state"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_RUNTIME_DIR": str(runtime),
        "DISPLAY": "", "WAYLAND_DISPLAY": "", "LANG": "C.UTF-8",
        "KARING_TUI_CORE_PATH": core,
    }


def configured_status(status: object) -> None:
    require(isinstance(status, dict), "invalid managed cold status")
    expected = {
        "api_version": "v1", "core_configured": True,
        "core_desired_state": "stopped", "core_state": "stopped",
        "recovery_required": False,
    }
    for key, value in expected.items():
        require(type(status.get(key)) is type(value) and status[key] == value,
                "unsafe cold Core status: " + key)
    for key in ("applied_generation_id", "last_known_good_generation_id", "core_pid"):
        require(status.get(key) is None or
                (key == "core_pid" and type(status[key]) is int and status[key] == 0),
                "cold managed Core unexpectedly has an applied generation or PID")
    require(status.get("core_circuit_open") in (None, False),
            "cold managed Core circuit opened")
    for key in ("config_revision", "declaration_revision"):
        require(type(status.get(key)) is int and status[key] == 0,
                "cold Core had an unexpected declaration/generation revision")


def configured_caps(doc: object) -> None:
    require(isinstance(doc, dict) and doc.get("api_version") == "v1",
            "invalid managed-capability schema")
    caps = doc.get("capabilities")
    require(isinstance(caps, dict), "missing managed capabilities")
    for k in boot.DENIED:
        require(caps.get(k) is False, "unapproved managed capability " + k)
    for k in ("core_lifecycle_api", "managed_apply_runtime",
              "core_supervision", "unix_socket_api", "sqlite_state"):
        require(caps.get(k) is True, "configured Core lost guarded capability " + k)


def no_proxy_listener() -> None:
    for port in CORE_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.settimeout(0.25)
            result = conn.connect_ex(("127.0.0.1", port))
            require(result != 0, "Core listener opened without applied generation")


def private_secret(root: Path) -> str:
    path = root / "state" / "karing-tui-v2" / "core-control.secret"
    boot.verify_private(path, 0o600, "file")
    info = path.lstat()
    require(info.st_nlink == 1 and info.st_size == 64,
            "managed Core secret metadata is unsafe")
    raw = path.read_bytes()
    try:
        value = raw.decode("ascii")
    except UnicodeError as exc:
        raise RuntimeError("managed Core secret is not hex") from exc
    require(bool(HEX64.fullmatch(value)), "managed Core secret is not 64 hex bytes")
    # Return only a digest to compare; never log or print the actual secret.
    return hashlib.sha256(raw).hexdigest()


def run_managed_cold(app: str, root: Path, env: dict, exercise_start: bool) -> tuple[dict, str]:
    log_path = root / "daemon.log"
    with log_path.open("ab") as logfile:
        process = subprocess.Popen([app, "daemon", "run"], env=env,
                                   stdin=subprocess.DEVNULL,
                                   stdout=logfile, stderr=logfile)
        try:
            deadline = time.monotonic() + 15
            status = None
            while time.monotonic() < deadline:
                require(process.poll() is None, "managed Daemon exited before readiness")
                attempt = subprocess.run([app, "status", "--json"], env=env,
                                         capture_output=True, text=True,
                                         check=False, timeout=3)
                if attempt.returncode == 0:
                    import json
                    status = json.loads(attempt.stdout)
                    break
                time.sleep(0.15)
            require(status is not None, "configured Core Daemon status unavailable")
            configured_status(status)
            import json
            configured_caps(json.loads(boot.checked([app, "capabilities"], env)))
            state = root / "state" / "karing-tui-v2"
            runtime = root / "runtime" / "karing-tui-v2"
            boot.verify_private(state, 0o700, "dir")
            boot.verify_private(runtime, 0o700, "dir")
            boot.verify_private(state / "state.db", 0o600, "file")
            boot.verify_private(runtime / "daemon.sock", 0o600, "socket")
            secret_digest = private_secret(root)
            no_proxy_listener()
            if exercise_start:
                # Explicit operator test only: a missing committed generation
                # MUST be rejected and MUST NOT spawn Core or gain a PID.
                result = subprocess.run([app, "core", "start"], env=env,
                                        capture_output=True, text=True,
                                        check=False, timeout=10)
                require(result.returncode != 0, "uncommitted Core started")
                after = json.loads(boot.checked([app, "status", "--json"], env))
                require(after.get("core_pid") in (None, 0) and
                        after.get("applied_generation_id") is None and
                        after.get("last_known_good_generation_id") is None and
                        after.get("core_state") == "stopped",
                        "failed start unexpectedly launched Core or applied generation")
                no_proxy_listener()
                # Current lifecycle intentionally preserves a failed *intent*.
                # Explicit stop is REQUIRED before ending experiment.
                boot.checked([app, "core", "stop"], env, timeout=15)
                configured_status(json.loads(
                    boot.checked([app, "status", "--json"], env)))
                no_proxy_listener()
            return status, secret_digest
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                code = process.wait(timeout=12)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("managed cold Daemon shutdown timeout") from exc
            require(code == 0, "managed cold Daemon did not stop cleanly")


def test_rejected_core_paths(app: str, root: Path, valid_core: str) -> None:
    link = root / "core-symlink"
    link.symlink_to(valid_core)
    unapproved = root / "unapproved-core"
    unapproved.write_bytes(b"not an approved Core binary\n")
    unapproved.chmod(0o500)
    for name, candidate in (("symlink", link), ("unapproved", unapproved)):
        target = root / ("reject-" + name)
        target.mkdir(mode=0o700)
        env = fresh_env(target, str(candidate))
        attempt = subprocess.run([app, "daemon", "run"], env=env,
                                 capture_output=True, text=True,
                                 check=False, timeout=8)
        require(attempt.returncode != 0,
                "unapproved Core path allowed Daemon startup")
        socket_path = target / "runtime" / "karing-tui-v2" / "daemon.sock"
        require(not socket_path.exists(),
                "rejected Core left a live daemon socket")
        require(not (target / "state" / "karing-tui-v2" /
                     "core-control.secret").exists(),
                "rejected Core created an authorization secret")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=boot.MACHINES)
    parser.add_argument("--app", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        boot.ensure_airgap(args.arch)
        for path in (args.app, args.core):
            require(Path(path).is_absolute() and Path(path).is_file() and
                    os.access(path, os.X_OK), "pre-staged test binary unavailable")
        hash_pinned_core(Path(args.core), args.core_sha256)
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="t24-managed-cold-", dir="/work") as tmp:
            root = Path(tmp)
            env = fresh_env(root, args.core)
            first, secret = run_managed_cold(args.app, root, env, True)
            second, same_secret = run_managed_cold(args.app, root, env, False)
            require(secret == same_secret, "control secret rotated on cold restart")
            for key in ("config_revision", "declaration_revision",
                        "core_desired_state", "applied_generation_id",
                        "last_known_good_generation_id"):
                require(first.get(key) == second.get(key),
                        "managed cold restart drifted persistent state: " + key)
            hash_pinned_core(Path(args.core), args.core_sha256)
            test_rejected_core_paths(args.app, root, args.core)
        print("T24_AIRGAP_MANAGED_CORE_COLD_GUARD=ok")
        print("T24_MANAGED_CORE_WITH_APPLIED_GENERATION_VERIFIED=false")
        print("T24_CN_OFFLINE_LICENSE_APPROVED=false")
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        print("T24_AIRGAP_MANAGED_CORE_COLD_GUARD=refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
