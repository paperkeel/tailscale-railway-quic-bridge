.PHONY: check format build

check:
	mise x go@1.26.5 -- go test -race ./...
	mise x go@1.26.5 -- go vet ./...
	files="$$(mise x go@1.26.5 -- gofmt -l .)" && test -z "$$files"

format:
	mise x go@1.26.5 -- gofmt -w .

build:
	mise x go@1.26.5 -- go build ./cmd/...
