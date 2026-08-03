# Repository instructions

Run `mise x go@1.26.5 -- go test ./...` before each commit.

Run `pnpm check:infra` and `pnpm test:infra` when you change SST deployment code.

Run `make validate-deploy` before each commit that changes deployment files.

Run `mise x go@1.26.5 -- gofmt -w .` to format Go files.

Keep runtime configuration in environment variables. Do not add runtime config files.

Keep the connector unprivileged. Restrict Linux network changes to the edge.

Update `docs/configuration.md` when you add or change an environment variable.

Use `docs/setup.md` as the only deployment procedure. Do not add provider-specific deployment guides.
