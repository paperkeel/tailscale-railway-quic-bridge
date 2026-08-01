# Contributing

1. Install Go 1.26.5 through `mise`.

2. Run the standard checks before you open a pull request:

   ```bash
   make check
   ```

3. Run the complete audit when you change the data path, network policy, images, or deployment files:

   ```bash
   make audit
   ```

   This command uses privileged Docker for the isolated network test. It does not deploy infrastructure.

4. Keep protocol changes backward compatible within one major version.

5. Add tests for configuration, protocol, routing, and security changes.

6. Do not include credentials, generated certificates, or user traffic.
