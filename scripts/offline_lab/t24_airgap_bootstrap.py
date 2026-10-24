#!/usr/bin/env python3
"""T24 PARTIAL native air-gapped bootstrap, never a CN bundle or release proof.

Runs inside a pre-staged, non-root, Docker --network none Linux container.
Exercises a prebuilt approved core's version/config CHECK (never start) and
starts the actual daemon twice with an isolated private SQLite + Unix socket.
Does not attest a CN SRS license, routing, DNS, power loss or restore.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import platform
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

MACHINES = {"amd64": "x86_64", "arm64": "aarch64"}
DENIED = ("core_distribution", "cn_preset_offline_bundle", "cn_preset",
          "proxy_inbounds", "subscriptions", "tui")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checked(argv, env, timeout=15):
    result = subprocess.run(argv, capture_output=True, text=True,
                            check=False, env=env, timeout=timeout)
    require(result.returncode == 0, "pre-staged binary failed")
    return result.stdout


def ensure_airgap(arch):
    require(sys.platform == "linux" and platform.machine() == MACHINES[arch],
            "native Linux architecture mismatch")
    require(os.geteuid() != 0, "root process is forbidden")
    require(os.environ.get("DISPLAY", "") == "" and
            os.environ.get("WAYLAND_DISPLAY", "") == "",
            "desktop must be unavailable")
    with open("/proc/self/status", encoding="ascii") as fd:
        caps = [s for s in fd if s.startswith("CapEff:")]
    require(len(caps) == 1 and int(caps[0].split()[1], 16) == 0,
            "effective Linux capabilities not dropped")
    # UDP connect does not transmit a packet; an isolated namespace has no
    # usable route to TEST-NET. Fail even if an outbound route is black-holed.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("203.0.113.1", 53))
        except OSError as exc:
            require(exc.errno in (
                errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN),
                "non-network route returned unexpected error")
        else:
            raise RuntimeError("non-loopback route exists")


def verify_core(core, expected_version, root, env):
    require(checked([core, "version", "-n"], env).strip() == expected_version,
            "core version differs from approved lock")
    # Use the known-good no-download, no-TUN config from runtime smoke.
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {"type": "mixed", "tag": tag, "listen": "127.0.0.1",
             "listen_port": port, "set_system_proxy": False}
            for tag, port in (
                ("rule-in", 28080), ("direct-in", 28081),
                ("selected-in", 28082))
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "selector", "tag": "selected",
             "outbounds": ["direct", "block"], "default": "direct"},
        ],
        "route": {
            "rules": [
                {"inbound": "direct-in", "outbound": "direct"},
                {"inbound": "selected-in", "outbound": "selected"},
            ],
            "final": "direct",
        },
        "experimental": {"clash_api": {
            "external_controller": "127.0.0.1:29090",
            "secret": "isolated-fake-secret",
            "default_mode": "Rule",
        }},
    }
    path = root / "core-check.json"
    path.write_text(json.dumps(config) + "\n", encoding="ascii")
    path.chmod(0o600)
    checked([core, "check", "-c", str(path)], env)


def verify_status(status):
    require(isinstance(status, dict), "invalid status response")
    for key, expected in {
        "api_version": "v1",
        "core_configured": False,
        "core_desired_state": "stopped",
        "core_state": "not-configured",
        "recovery_required": False,
    }.items():
        require(type(status.get(key)) is type(expected) and
                status[key] == expected, "unexpected offline status " + key)
    for key in ("applied_generation_id", "last_known_good_generation_id", "core_pid"):
        require(status.get(key) is None, "offline boot unexpectedly activated core")
    for key in ("config_revision", "declaration_revision"):
        require(type(status.get(key)) is int and status[key] >= 0,
                "invalid persistent revision")


def verify_caps(doc):
    require(isinstance(doc, dict) and doc.get("api_version") == "v1",
            "invalid capability payload")
    caps = doc.get("capabilities")
    require(isinstance(caps, dict), "capability map missing")
    for key in DENIED:
        require(caps.get(key) is False, "unapproved offline capability " + key)
    for key in ("sqlite_state", "unix_socket_api", "secure_runtime_paths"):
        require(caps.get(key) is True, "missing offline foundation " + key)


def verify_private(path, mode, kind):
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if kind == "dir" else
             stat.S_ISREG(info.st_mode) if kind == "file" else
             stat.S_ISSOCK(info.st_mode)), "wrong private artifact type")
    require(info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == mode,
            "private artifact owner/mode drift")


def start_daemon(app, root, env):
    logfile = root / "daemon.log"
    with logfile.open("ab") as output:
        child = subprocess.Popen([app, "daemon", "run"], env=env,
                                 stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=output)
        try:
            status = None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                require(child.poll() is None, "daemon terminated before readiness")
                attempt = subprocess.run(
                    [app, "status", "--json"], env=env, capture_output=True,
                    text=True, check=False, timeout=3)
                if attempt.returncode == 0:
                    status = json.loads(attempt.stdout)
                    break
                time.sleep(0.15)
            require(status is not None, "offline Unix status unavailable")
            verify_status(status)
            verify_caps(json.loads(checked([app, "capabilities"], env)))
            state = Path(env["XDG_STATE_HOME"]) / "karing-tui-v2"
            runtime = Path(env["XDG_RUNTIME_DIR"]) / "karing-tui-v2"
            verify_private(state, 0o700, "dir")
            verify_private(runtime, 0o700, "dir")
            verify_private(state / "state.db", 0o600, "file")
            verify_private(runtime / "daemon.sock", 0o600, "socket")
            return status
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            try:
                exit_code = child.wait(timeout=10)
            except subprocess.TimeoutExpired as exc:
                child.kill()
                child.wait(timeout=5)
                raise RuntimeError("daemon shutdown timeout") from exc
            require(exit_code == 0, "daemon did not stop cleanly")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=MACHINES)
    parser.add_argument("--app", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-version", required=True)
    args = parser.parse_args(argv)
    try:
        ensure_airgap(args.arch)
        for name in ("app", "core"):
            executable = Path(getattr(args, name))
            require(executable.is_absolute() and executable.is_file() and
                    os.access(executable, os.X_OK), "pre-staged executable missing")
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="t24-airgap-", dir="/work") as tmp:
            root = Path(tmp)
            env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(root),
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_DATA_HOME": str(root / "data"),
                "XDG_STATE_HOME": str(root / "state"),
                "XDG_CACHE_HOME": str(root / "cache"),
                "XDG_RUNTIME_DIR": str(root / "runtime"),
                "DISPLAY": "", "WAYLAND_DISPLAY": "", "LANG": "C.UTF-8",
            }
            (root / "runtime").mkdir(mode=0o700)
            checked([args.app, "version"], env)
            verify_core(args.core, args.core_version, root, env)
            first = start_daemon(args.app, root, env)
            second = start_daemon(args.app, root, env)
            for field in ("config_revision", "declaration_revision",
                          "core_desired_state", "core_configured",
                          "applied_generation_id", "last_known_good_generation_id"):
                require(first.get(field) == second.get(field),
                        "offline restart modified persistent " + field)
        print("T24_AIRGAP_NATIVE_BOOTSTRAP=ok")
        print("T24_FULL_CN_OFFLINE_BUNDLE_VERIFIED=false")
        print("T24_REAL_CORE_TRAFFIC_VERIFIED=false")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("T24_AIRGAP_NATIVE_BOOTSTRAP=refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
