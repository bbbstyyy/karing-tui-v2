#!/usr/bin/env bash
set -euo pipefail

core="${1:-}"
if [[ -z "$core" || ! -x "$core" ]]; then
  echo "usage: $0 <core-executable>" >&2
  exit 2
fi
if [[ "$(id -u)" -eq 0 ]]; then
  echo "runtime smoke must run as an ordinary user" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$repo_root/resources/core.lock.json"
expected_version="$(jq -r '.reference_linux_cli_build.version_value' "$lock")"

workdir="$(mktemp -d)"
pid=""
cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

config="$workdir/config.json"
log="$workdir/core.log"
secret="karing-tui-v2-smoke-secret"

cat >"$config" <<'JSON'
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "rule-in",
      "listen": "127.0.0.1",
      "listen_port": 28080,
      "set_system_proxy": false
    },
    {
      "type": "mixed",
      "tag": "direct-in",
      "listen": "127.0.0.1",
      "listen_port": 28081,
      "set_system_proxy": false
    },
    {
      "type": "mixed",
      "tag": "selected-in",
      "listen": "127.0.0.1",
      "listen_port": 28082,
      "set_system_proxy": false
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "selector",
      "tag": "selected",
      "outbounds": ["direct", "block"],
      "default": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": "direct-in",
        "outbound": "direct"
      },
      {
        "inbound": "selected-in",
        "outbound": "selected"
      }
    ],
    "final": "direct"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:29090",
      "secret": "karing-tui-v2-smoke-secret",
      "default_mode": "Rule"
    }
  }
}
JSON
chmod 600 "$config"

python3 - <<'PY'
import socket

ports = (28080, 28081, 28082, 29090)
sockets = []
try:
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", port))
        sockets.append(sock)
finally:
    for sock in sockets:
        sock.close()
PY

version_output="$("$core" version -n)"
if [[ "$version_output" != "$expected_version" ]]; then
  echo "version output mismatch: got '$version_output', want '$expected_version'" >&2
  exit 1
fi
echo "CORE_VERSION_NAME=$version_output"

"$core" check -c "$config"

"$core" run -c "$config" >"$log" 2>&1 &
pid=$!

ready=0
for _ in $(seq 1 100); do
  if ! kill -0 "$pid" 2>/dev/null; then
    cat "$log" >&2 || true
    echo "core exited before readiness" >&2
    exit 1
  fi
  code="$(curl --noproxy '*' -sS -o "$workdir/unauthorized.json" -w '%{http_code}' --max-time 1 "http://127.0.0.1:29090/version" || true)"
  if [[ "$code" == "401" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  cat "$log" >&2 || true
  echo "authenticated Clash API did not become ready on the configured port" >&2
  exit 1
fi

version_json="$(curl --noproxy '*' -fsS --max-time 2 -H "Authorization: Bearer $secret" "http://127.0.0.1:29090/version")"
python3 - "$version_json" "$expected_version" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
expected = sys.argv[2]
if payload.get("version") != "sing-box " + expected:
    raise SystemExit(f"unexpected version payload: {payload!r}")
if payload.get("premium") is not True or payload.get("meta") is not True:
    raise SystemExit(f"unexpected capability payload: {payload!r}")
PY

python3 - <<'PY'
import socket

for port in (28080, 28081, 28082):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.sendall(b"\x05\x01\x00")
        reply = sock.recv(2)
        if reply != b"\x05\x00":
            raise SystemExit(f"SOCKS5 greeting failed on {port}: {reply!r}")
PY

kill -TERM "$pid"
wait "$pid"
pid=""

echo "CORE_RUNTIME_SMOKE=ok"
