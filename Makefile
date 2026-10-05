.PHONY: build test test-race vet fmt-check

build:
	go build -trimpath ./cmd/karing-tui

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$(gofmt -l .)" || (echo "gofmt required:"; gofmt -l .; gofmt -d $(gofmt -l .); exit 1)
