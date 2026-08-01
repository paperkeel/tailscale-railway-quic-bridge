# Deploy the Tailbridge edge

Place the Tailbridge edge near the Railway region. A direct public IP gives Tailscale a direct UDP path.

## DigitalOcean with Terraform

1. Change to the deployment directory:

   ```bash
   cd deploy/digitalocean
   ```

2. Copy the example variables:

   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

3. Set the DigitalOcean token in `terraform.tfvars`.

4. Set the SSH key fingerprint in `terraform.tfvars`.

5. Set the authorized SSH CIDR in `terraform.tfvars`.

6. Select the region that is nearest to the Railway region.

7. Initialize Terraform:

   ```bash
   terraform init
   ```

8. Create the droplet:

   ```bash
   terraform apply
   ```

9. Record the `edge_ipv4` output.

10. Point the configured edge hostname to the `edge_ipv4` address.

11. Restrict the generated Tailbridge edge environment file:

    ```bash
    chmod 0600 ../../private/edge.env
    stat -c '%a %n' ../../private/edge.env
    ```

    The README procedure creates `private/edge.env` in the repository root. From this directory, the path is `../../private/edge.env`.

12. Copy the deployment files:

    ```bash
    scp ../docker-compose.edge.yml root@EDGE_IP:/opt/tailbridge/compose.yml
    scp ../../private/edge.env root@EDGE_IP:/opt/tailbridge/edge.env
    ```

13. Restrict the copied environment file:

    ```bash
    ssh root@EDGE_IP 'chmod 0600 /opt/tailbridge/edge.env'
    ```

14. Connect to the edge host:

    ```bash
    ssh root@EDGE_IP
    ```

15. Change to the Tailbridge directory:

    ```bash
    cd /opt/tailbridge
    ```

16. If the GHCR package is private, log in to GHCR:

    ```bash
    docker login ghcr.io
    ```

17. Pull the Tailbridge edge image:

    ```bash
    docker compose -f compose.yml pull
    ```

18. Start the Tailbridge edge:

    ```bash
    docker compose -f compose.yml up -d
    ```

The firewall permits UDP `41641` and `4433`. It permits SSH only from `ssh_source_addresses`.

## Manual host

1. Install Docker on a current Linux host.

2. Copy the Compose file to `/opt/tailbridge/compose.yml` on the host.

3. Copy the generated `edge.env` file to the host.

4. Enable packet forwarding on the host:

   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo sysctl -w net.ipv6.conf.all.forwarding=1
   ```

5. Save these settings in the host's sysctl configuration.

   The DigitalOcean template configures these settings automatically.

6. Open UDP port `41641`.

7. Open UDP port `4433`.

8. Start the Tailbridge edge:

   ```bash
   docker compose -f compose.yml up -d
   ```

9. Check the Tailbridge edge logs:

   ```bash
   docker compose -f compose.yml logs edge
   ```

10. Confirm that the Tailscale machine has the expected hostname.

11. Confirm that the Tailscale machine advertises `fd12::/16`.

## Persistent identity

1. Do not delete the `tailscale-state` volume during an upgrade.

   The volume preserves the Tailscale machine identity. `TS_AUTH_ONCE=true` stops repeated authentication.

2. Use a tagged, preauthorized, non-ephemeral auth key for the first start.

   You can also use a tagged OAuth client secret with `?ephemeral=false`.

   An ephemeral credential cannot preserve the identity after state loss.

3. Store a tagged, preauthorized, non-ephemeral credential in your recovery system.

4. Remove `TS_AUTHKEY` after the first successful start.

   The credential registers a node only when the state directory has no valid identity.
