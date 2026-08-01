# Repository instructions

Run `mise x go@1.26.5 -- go test ./...` before each commit.

Run `mise x go@1.26.5 -- gofmt -w .` to format Go files.

Keep runtime configuration in environment variables. Do not add runtime config files.

Keep the connector unprivileged. Restrict Linux network changes to the edge.

Update `docs/configuration.md` when you add or change an environment variable.
