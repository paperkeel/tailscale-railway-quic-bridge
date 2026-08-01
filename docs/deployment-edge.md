# Deploy the edge

Place the edge near the Railway region. A direct public IP gives Tailscale the best path.

## DigitalOcean with Terraform

Copy the example variables:

```bash
cd deploy/digitalocean
cp terraform.tfvars.example terraform.tfvars
```

Set the DigitalOcean token, SSH key fingerprint, and authorized SSH CIDR. Select the nearest region.

Create the droplet:

```bash
terraform init
terraform apply
```

Record the `edge_ipv4` output. Point the configured edge hostname to this address.

Copy the deployment files:

```bash
chmod 0600 ../../private/edge.env
stat -c '%a %n' ../../private/edge.env
scp ../docker-compose.edge.yml root@EDGE_IP:/opt/tailbridge/compose.yml
scp ../../private/edge.env root@EDGE_IP:/opt/tailbridge/edge.env
ssh root@EDGE_IP 'chmod 0600 /opt/tailbridge/edge.env'
```

The `../../private/edge.env` path is the output from the README setup command when you run these steps from `deploy/digitalocean`.

Log in to GHCR when the package is private:

```bash
ssh root@EDGE_IP
cd /opt/tailbridge
docker login ghcr.io
docker compose -f compose.yml pull
docker compose -f compose.yml up -d
```

The firewall permits UDP `41641` and `4433`. It permits SSH only from `ssh_source_addresses`.

## Manual host

Install Docker on a current Linux host. Copy the Compose file and generated `edge.env` file.

Enable packet forwarding on the host:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

Persist these settings with the host's sysctl configuration. The DigitalOcean template configures them automatically.

Open these ports:

```text
UDP 41641
UDP 4433
```

Start the edge:

```bash
docker compose -f compose.yml up -d
```

Check the logs:

```bash
docker compose -f compose.yml logs edge
```

Confirm that the Tailscale machine has the expected hostname. Confirm that it advertises `fd12::/16`.

## Persistent identity

Do not delete the `tailscale-state` volume during an upgrade.

The volume preserves the machine identity. `TS_AUTH_ONCE=true` stops repeated authentication.

Use a tagged, preauthorized, non-ephemeral auth key for the first start. You can also use a tagged OAuth client secret with `?ephemeral=false`. An ephemeral credential defeats stable identity after state loss.

The credential only registers a node when the state directory has no valid identity. Remove `TS_AUTHKEY` from the environment after the first successful start if your recovery process stores it elsewhere.
