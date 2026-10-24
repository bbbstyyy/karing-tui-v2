#!/bin/sh
# Run one deterministic slice of the full Go race test inventory.
# Every top-level Test/Example/Fuzz in backupclosure is discovered at build
# time and assigned exactly once; subtests remain with their parent.
# Shard 0 also runs every other Go package under -race. Do not add a skip list.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <zero-based-shard> <shard-count>" >&2
    exit 2
fi

shard=$1
total=$2
case "$shard:$total" in
    *[!0-9:]* | :* | *: ) echo "invalid shard arguments" >&2; exit 2 ;;
esac
if [ "$total" -lt 1 ] || [ "$total" -gt 16 ] || [ "$shard" -ge "$total" ]; then
    echo "invalid shard index/count: $shard/$total" >&2
    exit 2
fi

# Listing is compiled with the same platform/build tags as the test run.
# Capture and check exit status BEFORE text filtering (POSIX pipelines do
# not reliably propagate an earlier command's failure).
listed=$(go test ./internal/backupclosure -list '^(Test|Fuzz|Example)') || exit 1
names=$(printf '%s\n' "$listed" |
    LC_ALL=C grep -E '^(Test|Fuzz|Example)[A-Za-z0-9_]+$' |
    LC_ALL=C sort -u) || {
    echo "unable to enumerate backupclosure test names" >&2
    exit 1
}
count=$(printf '%s\n' "$names" | wc -l | tr -d ' ')
test "$count" -ge "$total" || {
    echo "backupclosure test inventory too small to form $total shards" >&2
    exit 1
}

# Sorted round-robin partition: no manually maintained allow/deny regex,
# and every new test is automatically included after any source change.
selection=$(printf '%s\n' "$names" |
    awk -v shard="$shard" -v total="$total" \
        '((NR-1) % total) == shard {
             printf "%s%s", (found++ ? "|" : ""), $0
         }') || exit 1
if [ -z "$selection" ]; then
    echo "empty backupclosure race shard $shard/$total" >&2
    exit 1
fi
selection="^($selection)$"
echo "Running backupclosure race shard $shard/$total (full inventory $count names)"
go test -race -count=1 -timeout 30m -run "$selection" ./internal/backupclosure

if [ "$shard" -eq 0 ]; then
    # All other Go packages are tested exactly once with race instrumentation.
    # Go import paths cannot contain whitespace. No package may be silently
    # removed from this list: only the separately sharded package is excluded.
    packages=$(go list ./... | grep -v '/internal/backupclosure$') || {
        echo "unable to enumerate remaining Go packages" >&2
        exit 1
    }
    if [ -n "$packages" ]; then
        echo "Running race tests for every other Go package"
        # Intentional word splitting over go-list import paths.
        # shellcheck disable=SC2086
        go test -race -count=1 -timeout 30m $packages
    fi
fi
