# Deploy a shared Tailbridge edge

This procedure deploys one shared Tailbridge edge for one through 32 Railway environments.

Each Railway environment uses one connector slot. Keep each slot stable after the first deployment.

## Choose a deployment method

Use the GitHub template for a standard deployment. You do not need to fork the Tailbridge source repository.

The template keeps your infrastructure configuration separate from the Tailbridge source. It also polls for tested `master` artifacts.

Import the `Tailbridge` SST component only when you need custom infrastructure code.

## Prerequisites

For a template deployment, you need these accounts and credentials:

- A GitHub account that can create a repository from a public template.
- A Cloudflare account with R2 enabled.
- A Cloudflare API token that can manage R2 state.
- A DigitalOcean API token that can manage droplets, firewalls, volumes, and SSH keys.
- A Railway token that can manage projects, environments, services, variables, and deployments.
- A Tailscale account that can change the tailnet policy.
- A tagged, preauthorized, non-ephemeral Tailscale auth key.
- A GitHub classic personal access token with the `read:packages` scope.

Authorize the GitHub token for organization single sign-on when the organization requires authorization.

For local or advanced use, you also need Node.js 22 or later and pnpm 10.34.5.

This procedure does not include Node.js or pnpm installation steps.

## Create the deployment repository

1. Open the [Tailbridge SST template](https://github.com/bearfire-dev/tailbridge-sst-template).

2. Select **Use this template**.

3. Create a repository in your GitHub account or organization.

4. Keep the default branch protection and Actions permissions required by your organization.

Do not create a fork of the Tailbridge source repository. A fork mixes infrastructure state with upstream source changes.

## Configure GitHub Packages access

The template installs `@bearfire-dev/tailscale-railway-quic-bridge` from `https://npm.pkg.github.com`.

1. Create a classic personal access token with the `read:packages` scope.

2. Grant the token access to the `bearfire-dev` package when GitHub requests package authorization.

3. Open the deployment repository settings.

4. Open **Environments**, and then open the `production` environment.

5. Add the token as the `GH_PACKAGES_TOKEN` environment secret.

Do not commit this token to `.npmrc`, `package.json`, or another repository file.

## Configure deployment secrets

Add these secrets to the GitHub `production` environment:

| Secret | Purpose |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Reads and writes encrypted SST state in Cloudflare R2. |
| `DIGITALOCEAN_TOKEN` | Manages the shared edge resources. |
| `RAILWAY_TOKEN` | Manages connector services and Railway settings. |
| `TAILSCALE_AUTH_KEY` | Registers the shared edge in the tailnet. |
| `GH_PACKAGES_TOKEN` | Reads the public GitHub Packages component. |

Keep all secret values outside repository files and workflow logs.

The workflow passes `TAILSCALE_AUTH_KEY` to SST through standard input. It does not write the value to a file.

An ephemeral Tailscale auth key cannot restore a stable edge identity after state loss.

## Define the shared edge

Add these variables to the GitHub `production` environment:

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `CLOUDFLARE_ACCOUNT_ID` | Yes | None | Selects the Cloudflare account for SST state. |
| `TAILBRIDGE_EDGE_ID` | No | `production` | Gives the shared edge a stable deployment identity. |
| `TAILBRIDGE_CONNECTORS_JSON` | Yes | None | Defines one through 32 Railway connectors. |
| `EDGE_SSH_SOURCE_CIDRS` | Yes | None | Allows administrative SSH source networks. |
| `DIGITALOCEAN_REGION` | No | `nyc3` | Selects the shared edge region. |
| `DIGITALOCEAN_SIZE` | No | `s-1vcpu-1gb` | Selects the shared edge droplet size. |
| `TAILBRIDGE_VIRTUAL_NETWORK` | No | `fd20::/11` | Contains the 32 virtual connector networks. |

Use a stable value such as `production` for `TAILBRIDGE_EDGE_ID`.

Do not change `TAILBRIDGE_EDGE_ID` after the first deployment. A change creates a different component identity.

Separate multiple values in `EDGE_SSH_SOURCE_CIDRS` with commas.

The workflow also adds its runner IPv4 address as a `/32` for that run.

## Define connector slots

Set `TAILBRIDGE_CONNECTORS_JSON` to a JSON array. Each item has these fields:

| Field | Required | Value |
|---|---:|---|
| `name` | Yes | Stable project name and DNS label. |
| `slot` | Yes | Unique integer from `0` through `31`. |
| `projectId` | Yes | Existing Railway project ID. |
| `environmentId` | Yes | Existing Railway environment ID. |
| `region` | No | Railway region for this connector. |
| `realPrefix` | No | Railway IPv6 prefix. The default is `fd12::/16`. |

For example:

```json
[
  {
    "name": "billing",
    "slot": 0,
    "projectId": "replace-me",
    "environmentId": "replace-me",
    "region": "us-west2",
    "realPrefix": "fd12::/16"
  },
  {
    "name": "analytics",
    "slot": 1,
    "projectId": "replace-me",
    "environmentId": "replace-me"
  }
]
```

Each slot maps to one virtual `/16` inside `fd20::/11`.

| Slot | Virtual prefix | Virtual Railway resolver |
|---:|---|---|
| `0` | `fd20::/16` | `fd20::10` |
| `1` | `fd21::/16` | `fd21::10` |
| `31` | `fd3f::/16` | `fd3f::10` |

Keep a project in the same slot during updates. A slot change changes every virtual address for that project.

Each connector translates its virtual prefix to `realPrefix`. This translation lets many Railway projects use the same real prefix.

## Configure Cloudflare R2 state

The template uses Cloudflare R2 as the SST home. SST encrypts secret values in the state.

Use the `production` stage for the standard workflow. Keep the same Cloudflare account, edge ID, app name, and stage.

Back up the R2 state according to your recovery policy. State loss can cause SST to propose duplicate resources.

An advanced SST app can use `SST_HOME=local`. Use local state only for a disposable test.

## Run the first deployment

1. Open the **Actions** tab in the deployment repository.

2. Select the **Tailbridge deployment** workflow.

3. Start a manual workflow run with an empty `package_version` input.

4. Confirm that the workflow resolves the `master` package tag to an exact package version.

5. Confirm that the workflow installs the exact package version without changing the repository lockfile.

6. Confirm that the type check and tests pass.

7. Review the SST diff in the workflow log.

8. Confirm that the diff uses the intended Cloudflare, DigitalOcean, Railway, and Tailscale accounts.

9. Confirm that the diff creates one shared edge and the configured connector services.

10. Confirm that the diff does not replace an existing DigitalOcean volume.

11. Let the workflow deploy the `production` stage.

The workflow creates the edge before it activates the connector services.

The edge uses one stable Tailscale identity. Each Railway connector opens an outbound QUIC session to the edge public IPv4 address.

The workflow stores the exact package version as the SST `artifactVersion` output.

The installed package metadata pins the matching edge and connector image digest pair.

## Configure the tailnet

1. Copy the generated policy fragment from the workflow output.

2. Merge the policy fragment into the tailnet policy.

3. Add narrow grants for the required users, virtual destinations, and ports.

4. Approve each assigned virtual `/16` when the policy does not approve routes automatically.

   For example, approve `fd20::/16` for slot `0` and `fd21::/16` for slot `1`.

   Do not approve the complete `fd20::/11` range.

5. Configure one split DNS entry for each connector.

For slot `0` with the name `billing`, use this entry:

```text
Domain: billing.railway.internal
Nameserver: fd20::10
```

For slot `1` with the name `analytics`, use this entry:

```text
Domain: analytics.railway.internal
Nameserver: fd21::10
```

6. Make each client accept subnet routes when its platform requires this setting.

The connector removes the project label before it sends the query to Railway DNS.

The connector returns only AAAA records. It translates each returned address into the connector virtual prefix.

Tailbridge supports UDP and TCP DNS queries.

## Verify the first deployment

1. Record the shared edge addresses, connector outputs, deployed artifacts, and status commands.

2. Run the edge status command from the workflow output.

3. Confirm that the edge reports all configured connector slots as ready.

4. Confirm that Tailscale shows the expected shared edge hostname and virtual route.

5. Run `tailscale ping` from an approved client to the shared edge.

6. Confirm that the result shows a direct path to the edge public IPv4 address.

7. Resolve a project-qualified Railway hostname from the approved client.

8. Confirm that the result contains only virtual AAAA addresses from the correct slot.

9. Connect to an approved Railway TCP service.

10. Test an approved Railway UDP service when the project uses UDP.

11. Confirm that another project slot cannot access an unapproved destination.

For example:

```bash
dig AAAA api.billing.railway.internal
curl http://api.billing.railway.internal:3000
```

## Poll for Tailbridge updates

The **Tailbridge deployment** workflow runs every hour at minute `17`.

It also runs after manual requests and selected configuration changes on `master`.

The push paths include `infra/**`, `sst.config.ts`, `package.json`, and `pnpm-lock.yaml`.

Each scheduled run resolves the `master` package tag to an exact immutable version.

The workflow compares that exact version with the SST `artifactVersion` output.

During a scheduled run, the workflow stops when `artifactVersion` matches the resolved version.

Push and manual runs deploy even when the artifact version matches.

If the artifacts changed, the workflow creates a temporary dependency update. It does not commit the update.

The workflow then runs the type check, tests, SST diff, and production deployment.

Review scheduled deployment failures in GitHub Actions. Do not ignore a failed diff, test, or readiness check.

## Roll back an update

1. Find the last working exact package version in a successful workflow run.

2. Start a manual **Tailbridge deployment** workflow.

3. Enter the exact package version in `package_version`.

   Use the `0.0.0-sha.FULL_COMMIT_SHA` format.

4. Confirm that the workflow resolves the matching immutable image digest pair.

5. Review the SST diff.

6. Confirm that the diff keeps the existing edge volume and connector slots.

7. Deploy the previous package version.

8. Repeat the verification procedure.

Do not remove the SST stage to roll back an update.

The next hourly poll can replace the rollback when `master` points to a newer version.

Disable the scheduled workflow when you must keep the rollback version.

The old Railway connector deployment drains for 15 seconds after the replacement becomes ready.

An edge update causes a short outage. The persistent volume keeps the Tailscale machine identity.

## Change Railway projects

1. Edit `TAILBRIDGE_CONNECTORS_JSON` in the deployment repository settings.

2. Keep every existing project in its current slot.

3. Assign each new project an unused slot from `0` through `31`.

4. Start a manual deployment workflow.

5. Review all connector additions, updates, and removals in the SST diff.

6. Deploy the project change.

7. Update the tailnet grants and split DNS entries.

8. Verify every changed project.

If you remove an item, SST removes the managed connector service.

SST does not remove the referenced Railway project or environment.

Change `realPrefix` only when Railway changes the real project network. This change can interrupt active flows.

## Import the component into another SST app

Use this method only when the template cannot express your infrastructure requirements.

1. Configure the GitHub Packages registry for the `@bearfire-dev` scope.

2. Set `NODE_AUTH_TOKEN` to a classic GitHub token with the `read:packages` scope.

3. Add the component package to the SST project:

   ```bash
   pnpm add @bearfire-dev/tailscale-railway-quic-bridge
   ```

4. Import and create the component in `sst.config.ts`:

   ```typescript
   import { Tailbridge } from '@bearfire-dev/tailscale-railway-quic-bridge';

   const deployment = new Tailbridge('Tailbridge', {
     stage: $app.stage,
     edgeId: 'production',
     virtualNetwork: 'fd20::/11',
     edge: {
       provider: 'digitalocean',
       region: 'nyc3',
       size: 's-1vcpu-1gb',
       sshSourceCidrs: ['203.0.113.10/32'],
     },
     connectors: [
       {
         name: 'billing',
         slot: 0,
         projectId: 'replace-me',
         environmentId: 'replace-me',
         region: 'us-west2',
       },
     ],
     tailscaleAuthKey: new sst.Secret('TailscaleAuthKey').value,
   });
   ```

5. Keep the component name, app name, edge ID, and stage stable after the first deployment.

The component manages the edge, connector services, certificates, and deployment artifact marker. It also produces the tailnet policy data.

## Migrate an existing deployment

Do not let SST create replacements for a working edge or persistent volume.

1. Back up the current SST state and DigitalOcean volume.

2. Record all DigitalOcean, Railway, and Tailscale resource IDs.

3. Create the template repository and configure the same provider accounts.

4. Assign the existing Railway environment a stable connector slot.

5. Add an `import` option to each existing provider resource in a custom component copy.

   ```typescript
   new digitalocean.Droplet('Edge', args, {
     import: 'existing-droplet-id',
   });
   ```

6. Add the correct provider ID to each resource `import` option.

7. Run the SST diff.

8. Confirm that the diff preserves the edge host, volume, Tailscale identity, and Railway services.

9. Stop the previous deployment system from managing the imported resources.

10. Deploy the imported component.

11. Add the new virtual route and project-qualified DNS entry.

12. Verify the virtual service addresses.

13. Remove the old direct Railway route after clients use the virtual route.

Resource types and provider import IDs depend on the source deployment.

The published component does not expose resource import options. Use a custom component copy for this migration.

Remove each `import` option after SST records the resource in the `production` stage.

Do not import a resource that another deployment system still manages.

## Recover a failed workflow

1. Keep the failed SST stage and its R2 state.

2. Correct the reported secret, variable, package, or provider error.

3. Start the deployment workflow again.

4. Review the remaining SST changes.

5. Deploy the stage.

SST resumes from its stored state. The DigitalOcean volume keeps the edge identity when the volume remains available.

If the workflow package update fails, use the last working exact package version in a manual run.

If the R2 state is lost, restore the state before another deployment.

Do not deploy with empty state over existing cloud resources.

If SST retained the volume, import it before you deploy a replacement component.

If the volume is lost, store a new non-ephemeral Tailscale auth key. Validate the new machine before you remove the old machine.

## Remove Tailbridge

This action removes managed cloud resources. SST retains the DigitalOcean identity volume.

1. Stop scheduled deployment workflows.

2. Record the resource IDs and Tailscale machine ID.

3. Clone the deployment repository to an authenticated workstation.

4. Export the same provider credentials and deployment variables.

5. Set `NODE_AUTH_TOKEN` to the GitHub Packages token.

6. Install the locked dependencies:

   ```bash
   pnpm install --frozen-lockfile
   ```

7. Export and back up the SST state:

   ```bash
   pnpm sst state export --stage production > tailbridge-production-state.json
   ```

   Treat the exported state as a secret.

8. Confirm the ownership of every imported or external resource.

9. Remove the route approval, grants, and split DNS entries.

10. Remove the `production` stage:

   ```bash
   pnpm sst remove --stage production
   ```

11. Confirm that SST removed only resources that the component owns.

12. Confirm that Railway retains each referenced project and environment.

13. Remove the offline shared edge machine from Tailscale.

14. Keep the DigitalOcean volume until the identity recovery period ends.

15. Delete the retained volume only when you intend to discard the identity.

16. Remove the production environment secrets when no deployment uses them.

## Common errors

### GitHub Packages returns `401` or `403`

Confirm that `GH_PACKAGES_TOKEN` contains a classic token with `read:packages`.

Authorize the token for organization single sign-on when GitHub requires authorization.

### A required secret or variable is empty

Compare the repository settings with the names in this procedure. GitHub secret and variable names are case-sensitive.

### `TAILBRIDGE_CONNECTORS_JSON` is not valid

Validate the value as a JSON array. Remove comments and trailing commas.

Confirm that each item has a name, slot, project ID, and environment ID.

### A connector slot is outside the valid range

Use one unique integer from `0` through `31` for each connector.

### Two connectors use the same slot or name

Assign a unique stable name and slot to each connector.

### The scheduled workflow does not deploy

Check the resolved package version and the SST `artifactVersion` output.

The workflow correctly stops when the exact package version did not change.

The exact package version pins the same edge and connector image digest pair.

### SST proposes a new edge

Stop the deployment. Confirm the app name, stage, `TAILBRIDGE_EDGE_ID`, Cloudflare account, and R2 state.

### SST reports a state lock

Confirm that no other workflow or local deployment still runs.

Use the SST unlock command only after the first deployment stops.

### The workflow cannot connect to the edge through SSH

Confirm that the workflow added its current runner IPv4 address as a `/32`.

Confirm that the DigitalOcean firewall also contains the approved administrative CIDRs.

### A connector does not become ready

Confirm the Railway token, project ID, environment ID, region, and connector service logs.

Confirm that Railway can send outbound IPv4 UDP traffic to edge port `4433`.

### A project hostname does not resolve

Confirm that the split DNS suffix contains the connector name.

Confirm that the nameserver is the virtual resolver address for the connector slot.

### A virtual address does not accept traffic

Confirm that the client accepts subnet routes. Confirm that the tailnet grant permits the virtual destination and port.

Confirm that the Railway service listens on its private IPv6 address. Confirm that `realPrefix` contains that address.
