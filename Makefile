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
	@test -z "$$(gofmt -l .)" || (echo "gofmt required:"; gofmt -l .; exit 1)
