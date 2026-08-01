# Contributing

Install Go 1.26.5 through `mise`.

Run these checks before a pull request:

```bash
mise x go@1.26.5 -- go test -race ./...
mise x go@1.26.5 -- go vet ./...
mise x go@1.26.5 -- go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
unformatted="$(mise x go@1.26.5 -- gofmt -l .)" || exit 1
test -z "$unformatted"
```

Keep protocol changes backward compatible within one major version.

Add tests for configuration, protocol, routing, and security changes.

Do not include credentials, generated certificates, or user traffic.
