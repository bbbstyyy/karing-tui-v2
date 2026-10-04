.PHONY: build test vet fmt-check

build:
	go build -trimpath ./cmd/karing-tui

test:
	go test ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt required:"; gofmt -l .; exit 1)
