# Deploy Tailbridge

This procedure deploys one shared Tailbridge edge. Separate private repositories deploy Railway connectors as third-party users do.

Do not deploy infrastructure from the Tailbridge source repository.

## Choose artifact channels

Use the `stable` connector image tag for the standard Railway template:

```text
ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-connector:stable
```

Railway can follow a changed digest for this tag during a maintenance window. Use the `master` tag only for an explicit canary. A merge to the Tailbridge `master` branch updates that tag.

Use a `sha-FULL_COMMIT_SHA` tag or an image digest for rollback.

The SST package contains immutable edge and connector digests. Use an exact package version in a production deployment repository.

## Prepare Tailscale

1. Choose one tag for the edge and one tag for CI.

   Example values are `tag:tailbridge` and `tag:tailbridge-ci`.

2. Create a Tailscale workload identity for GitHub Actions.

3. Give the identity the `auth_keys` scope and the CI tag.

4. Store its client ID and audience as organization variables named `TS_OAUTH_CLIENT_ID` and `TS_AUDIENCE`.

   These values are not signing credentials.

5. Give the CI tag access to the edge approval port.

6. Give the edge tag authority to advertise the selected virtual pool.

7. Create a tagged, preauthorized, non-ephemeral auth key for the edge.

8. Store the key as `TAILSCALE_AUTH_KEY` in the private SST deployment repository.

The default pool is `fd40::/10`. It provides 64 `/16` allocations. Do not use a pool that overlaps Railway's `fd12::/16` prefix or another tailnet route.

The edge tag is configurable. Do not depend on the example tag names in an adopter environment.

## Prepare an OIDC profile

Tailbridge uses generic OIDC policies. GitHub is the standard profile.

1. Create the organization repository property `tailbridge_railway_project_id`.

2. Set the property to the Railway project ID on each deployment repository.

3. Include that custom property in GitHub Actions OIDC tokens.

   GitHub emits it as `repo_property_tailbridge_railway_project_id`.

   GitHub currently marks [repository custom properties in OIDC tokens](https://docs.github.com/en/actions/reference/security/oidc#including-repository-custom-properties-in-oidc-tokens) as a public preview. Review that status before you make this profile a production dependency. Use a different configured claim or identity provider if your GitHub plan does not provide the feature.

4. Require every deployment job to use a GitHub environment.

5. Use the Railway environment name as the GitHub environment name.

   GitHub creates a referenced environment when it does not exist. Apply organization rules that are suitable for preview environments.

6. Pin the reusable Tailbridge workflow by a full commit SHA.

7. Keep two approved workflow references during a workflow update. Remove the old reference after all callers use the new one.

Use a policy in this form. Replace every example value:

```json
[
  {
    "id": "github",
    "issuer": "https://token.actions.githubusercontent.com",
    "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
    "audiences": ["tailbridge-enrollment"],
    "algorithms": ["RS256"],
    "maxTokenAge": "5m",
    "requiredClaims": {
      "repository_owner_id": "REPLACE_WITH_ORGANIZATION_ID"
    },
    "oneOfClaims": {
      "job_workflow_ref": [
        "bearfire-dev/tailscale-railway-quic-bridge/.github/workflows/tailbridge-enroll.yml@FULL_COMMIT_SHA"
      ]
    },
    "projectIdClaim": "repo_property_tailbridge_railway_project_id",
    "environmentClaim": "environment",
    "replayClaim": "jti",
    "repositoryIdClaim": "repository_id",
    "repositoryClaim": "repository",
    "workflowRefClaim": "job_workflow_ref",
    "workflowShaClaim": "job_workflow_sha",
    "runIdClaim": "run_id",
    "runAttemptClaim": "run_attempt"
  }
]
```

The edge validates `exp`, `nbf`, `iat`, `jti`, the issuer, the audience, and all configured binding claims. It records the repository and workflow-run claims as audit data.

## Deploy the edge from a private SST repository

1. Create a private infrastructure repository.

2. Configure the `@bearfire-dev` GitHub Packages registry.

3. Install an exact Tailbridge package version:

   ```bash
   pnpm add @bearfire-dev/tailscale-railway-quic-bridge@0.0.0-sha.FULL_COMMIT_SHA
   ```

4. Define the edge in `sst.config.ts`:

   ```typescript
   import { Tailbridge } from "@bearfire-dev/tailscale-railway-quic-bridge";

   const tailbridge = new Tailbridge("Tailbridge", {
     stage: $app.stage,
     edgeId: "production",
     edge: {
       provider: "digitalocean",
       region: "nyc3",
       size: "s-1vcpu-1gb",
       sshSourceCidrs: ["192.0.2.0/24"],
     },
     registration: {
       frozen: false,
       newProjectsFrozen: true,
       allowedProjectIds: ["REPLACE_WITH_FIRST_PROJECT_ID"],
       virtualNetwork: "fd40::/10",
       excludedPrefixes: ["fd12::/16"],
       oidcPolicies: OIDC_POLICIES,
       approvalTailscaleTags: ["tag:tailbridge-ci"],
       edgeTailscaleTag: "tag:tailbridge",
       leases: {
         preview: "24h",
         persistent: "720h",
         quarantine: "24h",
       },
     },
     tailscaleAuthKey: TAILSCALE_AUTH_KEY,
   });
   ```

5. Keep `connectors` only while you migrate existing static connectors. Remove it after all active identities exist in SQLite.

6. Review the SST diff.

7. Confirm that the DigitalOcean volume has `retainOnDelete` protection.

8. Confirm that the edge container has separate mounts for Tailscale state and the SQLite registry.

9. Deploy from the private repository.

The dynamic route reconciler is the only writer for advertised routes. Do not add `--advertise-routes` to `TS_EXTRA_ARGS`.

Back up the DigitalOcean volume with a separate snapshot or backup policy. `retainOnDelete` prevents an SST delete from removing the volume. It is not a backup.

## Configure the Railway connector template

Create the template in the Railway workspace that will own the connectors.

1. Use this public image by default:

   ```text
   ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-connector:stable
   ```

2. Enable image updates for a changed `stable` digest.

3. Set one replica.

4. Attach one volume at `/var/lib/tailbridge`.

5. Set `RAILWAY_RUN_UID=65532` so the unprivileged connector can use the volume.

6. Set the health path to `/readyz`.

7. Set the health timeout to at least 30 minutes for the first enrollment.

8. Use the `ALWAYS` restart policy.

9. Set a 15-second drain period.

10. Disable deployment overlap. Railway cannot mount one volume on two deployments at the same time.

11. Set these non-secret variables:

    ```text
    TB_REGISTRATION_MODE=dynamic
    TB_IDENTITY_DIR=/var/lib/tailbridge
    TB_EDGE_ID=REPLACE_WITH_EDGE_ID
    TB_EDGE_ENDPOINT=REPLACE_WITH_EDGE_IP:4433
    TB_REGISTRATION_ENDPOINT=REPLACE_WITH_EDGE_IP:4434
    TB_TRUST_BUNDLE_B64=REPLACE_WITH_PUBLIC_ROOT_BUNDLE
    ```

Do not put Railway project IDs in template secrets. The connector reads Railway system variables at runtime.

Do not add static certificate, virtual-prefix, DNS-suffix, or lease-class variables to this template.

## Enroll a connector from its private project repository

1. Create the connector service from the Railway template.

2. Add `RAILWAY_TOKEN` as a repository or organization secret.

   Do not define `RAILWAY_TOKEN` in a selectable GitHub environment. The reusable workflow binds the job to the Railway environment name for OIDC. Protect those environments with deployment rules.

3. Call `.github/workflows/tailbridge-enroll.yml` from this repository by a full commit SHA.

4. Pass the Railway project ID, environment ID, environment name, connector service ID, DNS aliases, edge endpoints, approval URL, and trust bundle.

5. Pass `RAILWAY_TOKEN` as the reusable workflow secret `railway-token`.

The reusable workflow performs these actions:

1. It creates a random enrollment nonce.

2. It writes the nonce and connector variables through the Railway control plane.

3. It redeploys the connector.

4. It joins the tailnet with Tailscale workload identity federation.

5. It finds the pending registration.

6. It requests a GitHub OIDC token for `tailbridge-enrollment`.

7. It submits the nonce, fingerprint, and OIDC token to the tailnet-only approval API.

8. It waits for the connector session and route generation to become ready through the tailnet-only approval API.

The edge approves only an HMAC that uses the Railway-delivered nonce. Public project and environment IDs are not enough to claim an identity.

The approval API uses HTTP only after the runner joins Tailscale. Tailscale authenticates the caller and encrypts the connection with WireGuard. Do not expose the approval listener outside the tailnet.

## Configure split DNS

Create one Tailscale split-DNS entry:

```text
Domain: railway.internal
Nameserver: REPLACE_WITH_EDGE_TAILSCALE_IP
```

Use approved aliases in this name form:

```text
service.project-alias.environment-alias.railway.internal
```

The resolver returns `NXDOMAIN` for an unknown alias. It returns `SERVFAIL` when the connector is temporarily unavailable.

## Handle previews

Use the Railway preview environment name as the GitHub environment name.

A preview registration has a 24-hour lease unless its environment name is in `TB_PERSISTENT_ENVIRONMENTS`.

Call the reusable workflow with `operation: revoke` when a preview closes. Revocation withdraws the route, rejects new sessions, and starts the quarantine period.

If cleanup does not run, lease expiry withdraws the route automatically.

## Operate the freeze controls

Set `registration.frozen` to `true` to block all new requests and approvals.

Set `registration.newProjectsFrozen` to `true` to block unknown projects while you continue to create environments for known projects.

Use `allowedProjectIds` for an explicit first-project rollout.

Change these values only through an SST deployment. Tailbridge has no public freeze-control endpoint.

Existing data sessions and known-identity certificate renewals continue during a freeze.

## Revoke and recover

Use the reusable cleanup operation for normal preview removal.

A revoked route stays in quarantine for 24 hours by default. Tailbridge does not assign that prefix to another project during quarantine.

If a connector loses its volume, revoke the old registration and complete a new enrollment. Do not treat volume loss as an in-place key rotation because the old key cannot prove the new key.

Restore the DigitalOcean volume before you restore the edge. The volume contains the Tailscale machine identity, connector registry, leases, allocations, and certificate records.

## Roll back

1. Select the last working exact SST package version.

2. Select its matching image digests or `sha-FULL_COMMIT_SHA` tags.

3. Review the SST diff.

4. Confirm that the diff keeps the DigitalOcean volume and reserved IP.

5. Deploy from the private infrastructure repository.

6. Verify route reconciliation, DNS, TCP, UDP, certificate renewal, and revocation.

Do not use the mutable `master` image tag for rollback.
