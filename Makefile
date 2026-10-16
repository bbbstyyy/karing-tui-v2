.PHONY: build test test-race vet fmt-check

build:
	go build -trimpath ./cmd/karing-tui

test:
	go test ./...

# Encrypted archive/SQLite recovery fixtures are deliberately expensive under
# the race detector; never reduce test coverage to fit Go's default 10m budget.
test-race:
	go test -race -timeout 30m ./...

vet:
	go vet ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	 if test -n "$$unformatted"; then \
	   printf 'gofmt required:\n%s\n' "$$unformatted"; \
	   printf '%s\n' "$$unformatted" | while IFS= read -r file; do gofmt -d "$$file"; done; \
	   exit 1; \
	 fi
