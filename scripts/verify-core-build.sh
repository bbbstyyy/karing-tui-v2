#!/usr/bin/env bash
set -euo pipefail

arch="${1:-}"
case "$arch" in
  amd64|arm64) ;;
  *)
    echo "usage: $0 <amd64|arm64>" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$repo_root/resources/core.lock.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

expected_go="$(jq -r '.reference_linux_cli_build.go_version' "$lock")"
actual_go="$(go env GOVERSION)"
if [[ "$actual_go" != "go$expected_go" ]]; then
  echo "unexpected Go version: got $actual_go, want go$expected_go" >&2
  exit 1
fi

workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
mkdir -p "$workspace/KaringX"

clone_exact() {
  local url="$1"
  local commit="$2"
  local destination="$3"

  git init -q "$destination"
  git -C "$destination" remote add origin "$url"
  git -C "$destination" fetch -q --depth=1 origin "$commit"
  git -C "$destination" checkout -q --detach FETCH_HEAD

  local actual
  actual="$(git -C "$destination" rev-parse HEAD)"
  if [[ "$actual" != "$commit" ]]; then
    echo "commit mismatch for $url: got $actual, want $commit" >&2
    exit 1
  fi
}

core_url="$(jq -r '.source_repository' "$lock")"
core_commit="$(jq -r '.candidate_commit' "$lock")"
core_dir="$workspace/KaringX/sing-box"
clone_exact "$core_url" "$core_commit" "$core_dir"

while IFS=$'\t' read -r module url commit name; do
  destination="$workspace/KaringX/$name"
  clone_exact "$url" "$commit" "$destination"

  actual_module="$(sed -n 's/^module[[:space:]]\+//p' "$destination/go.mod" | head -n1)"
  if [[ "$actual_module" != "$module" ]]; then
    echo "module mismatch for $name: got $actual_module, want $module" >&2
    exit 1
  fi
done < <(
  jq -r '.local_replacements[] | [.module, .repository, .commit, (.repository | split("/")[-1])] | @tsv' "$lock"
)

cd "$core_dir"

base_tags="$(cat release/DEFAULT_BUILD_TAGS_OTHERS)"
expected_tags="$(jq -r '.fixed_makefile_evidence.default_tags' "$lock")"
if [[ "$base_tags" != "$expected_tags" ]]; then
  echo "build tag drift detected" >&2
  echo "got:  $base_tags" >&2
  echo "want: $expected_tags" >&2
  exit 1
fi
extra_tags="$(jq -r '.reference_linux_cli_build.extra_tags | join(",")' "$lock")"
actual_tags="$base_tags"
if [[ -n "$extra_tags" ]]; then
  actual_tags="$actual_tags,$extra_tags"
fi
entrypoint="$repo_root/resources/core-entry/main.go.txt"
if [[ ! -f "$entrypoint" ]]; then
  echo "core entrypoint template is missing" >&2
  exit 1
fi
mkdir -p "$core_dir/cmd/karing-tui-core"
cp "$entrypoint" "$core_dir/cmd/karing-tui-core/main.go"
echo "CORE_BUILD_TAGS=$actual_tags"
echo "CORE_ENTRYPOINT=cmd/karing-tui-core"

actual_ldflags="$(cat release/LDFLAGS)"
expected_ldflags="$(jq -r '.fixed_makefile_evidence.ldflags' "$lock")"
if [[ "$actual_ldflags" != "$expected_ldflags" ]]; then
  echo "ldflags drift detected" >&2
  exit 1
fi

version="$(jq -r '.reference_linux_cli_build.version_value' "$lock")"
out="$workspace/sing-box-linux-$arch"
ldflags="-X github.com/sagernet/sing-box/constant.Version=$version $actual_ldflags -s -w -buildid="

export GOTOOLCHAIN=local
export CGO_ENABLED=0
export GOOS=linux
export GOARCH="$arch"

go build -trimpath   -o "$out"   -tags "$actual_tags"   -ldflags "$ldflags"   ./cmd/karing-tui-core

file "$out"
sha="$(sha256sum "$out" | awk '{print $1}')"
echo "CORE_SHA256_LINUX_${arch^^}=$sha"

expected_sha="$(jq -r --arg arch "$arch" '.build_verification[$arch + "_sha256"] // empty' "$lock")"
if [[ -n "$expected_sha" && "$sha" != "$expected_sha" ]]; then
  echo "core SHA-256 mismatch for $arch: got $sha, want $expected_sha" >&2
  exit 1
fi

machine="$(uname -m)"
native=0
case "$arch:$machine" in
  amd64:x86_64|arm64:aarch64|arm64:arm64)
    native=1
    ;;
esac
if [[ "$native" == "1" ]]; then
  echo "CORE_NATIVE_RUNTIME_ARCH=$arch"
  "$repo_root/scripts/smoke-core-runtime.sh" "$out"
else
  echo "CORE_NATIVE_RUNTIME_SKIPPED=$arch-on-$machine"
fi
