.PHONY: build test test-race test-race-shard vet fmt-check

build:
	go build -trimpath ./cmd/karing-tui

test:
	go test ./...

# Race regression must keep every encrypted archive/SQLite failure fixture.
# Four complete, disjoint dynamic test slices prevent a single package's
# cumulative duration from exceeding Go's 30-minute per-process timeout.
# Locally, make test-race runs all shards serially; CI runs them in parallel.
RACE_SHARDS ?= 4
RACE_SHARD ?= 0

test-race:
	@shard=0; while test "$shard" -lt "$(RACE_SHARDS)"; do \
	  sh scripts/test-race-shard.sh "$shard" "$(RACE_SHARDS)" || exit $?; \
	  shard=$((shard + 1)); \
	done

test-race-shard:
	sh scripts/test-race-shard.sh "$(RACE_SHARD)" "$(RACE_SHARDS)"

vet:
	go vet ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	 if test -n "$$unformatted"; then \
	   printf 'gofmt required:\n%s\n' "$$unformatted"; \
	   printf '%s\n' "$$unformatted" | while IFS= read -r file; do gofmt -d "$$file"; done; \
	   exit 1; \
	 fi
