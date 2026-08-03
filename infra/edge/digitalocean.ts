import * as command from "@pulumi/command";
import * as digitalocean from "@pulumi/digitalocean";
import * as pulumi from "@pulumi/pulumi";

import type { EdgeDeployment, EdgeDeploymentArgs } from "./provider";
import {
	deploymentHash,
	renderCloudInit,
	renderCompose,
	renderEdgeEnvironment,
} from "./runtime";

const volumeLabel = "tailbridge";
const stateDirectory = "/var/lib/tailbridge";
const deploymentDirectory = "/opt/tailbridge";

export const edgeVolumeResourceOptions: pulumi.CustomResourceOptions =
	Object.freeze({ retainOnDelete: true });

export function edgeFirewallRules(
	sshSourceCidrs: string[],
): Pick<digitalocean.FirewallArgs, "inboundRules" | "outboundRules"> {
	return {
		inboundRules: [
			{
				protocol: "tcp",
				portRange: "22",
				sourceAddresses: sshSourceCidrs,
			},
			{
				protocol: "udp",
				portRange: "41641",
				sourceAddresses: ["0.0.0.0/0", "::/0"],
			},
			{
				protocol: "udp",
				portRange: "4433",
				sourceAddresses: ["0.0.0.0/0", "::/0"],
			},
		],
		outboundRules: [
			{
				protocol: "icmp",
				destinationAddresses: ["0.0.0.0/0", "::/0"],
			},
			{
				protocol: "tcp",
				portRange: "1-65535",
				destinationAddresses: ["0.0.0.0/0", "::/0"],
			},
			{
				protocol: "udp",
				portRange: "1-65535",
				destinationAddresses: ["0.0.0.0/0", "::/0"],
			},
		],
	};
}

export function createDigitalOceanEdge(
	args: EdgeDeploymentArgs,
): EdgeDeployment {
	const { certificates, tailscaleAuthKey } = args;
	const resourceName = physicalName(args.edgeId, 48);
	const childOptions = { parent: args.parent };

	const sshKey = new digitalocean.SshKey(`${args.name}-edge-ssh-key`, {
		name: `${resourceName}-ssh`,
		publicKey: certificates.sshPublicKey,
	}, childOptions);

	const volume = new digitalocean.Volume(
		`${args.name}-edge-state`,
		{
			name: `${resourceName}-state`,
			region: args.edge.region,
			size: 10,
			initialFilesystemType: "ext4",
			initialFilesystemLabel: volumeLabel,
			description: "Tailbridge edge state",
		},
		{ ...edgeVolumeResourceOptions, ...childOptions },
	);

	const droplet = new digitalocean.Droplet(`${args.name}-edge-host`, {
		name: resourceName,
		image: "ubuntu-24-04-x64",
		region: args.edge.region,
		size: args.edge.size,
		sshKeys: [sshKey.fingerprint],
		ipv6: true,
		monitoring: true,
		gracefulShutdown: true,
		userData: renderCloudInit(),
		tags: ["tailbridge", resourceName],
	}, childOptions);

	const firewall = new digitalocean.Firewall(`${args.name}-edge-firewall`, {
		name: `${resourceName}-firewall`,
		dropletIds: [droplet.id.apply(Number)],
		...edgeFirewallRules(args.edge.sshSourceCidrs),
	}, childOptions);

	const attachment = new digitalocean.VolumeAttachment(`${args.name}-edge-state-attachment`, {
		dropletId: droplet.id.apply(Number),
		volumeId: volume.id,
	}, childOptions);

	const connection: command.types.input.remote.ConnectionArgs = {
		host: droplet.ipv4Address,
		user: "root",
		privateKey: certificates.sshPrivateKey,
		dialErrorLimit: 30,
		perDialTimeout: 10,
	};

	const prepare = new command.remote.Command(
		`${args.name}-edge-prepare`,
		{
			connection,
			create: prepareCommand(volume.name),
			update: prepareCommand(volume.name),
			triggers: [volume.id, droplet.id],
		},
		{ parent: args.parent, dependsOn: [attachment, firewall] },
	);

	const compose = renderCompose(args.image);
	const environment = pulumi
		.all([
			certificates.caCertB64,
			certificates.edgeCertB64,
			certificates.edgeKeyB64,
			tailscaleAuthKey,
		])
		.apply(([caCertB64, edgeCertB64, edgeKeyB64, authKey]) =>
			renderEdgeEnvironment({
				edgeId: args.edgeId,
				environment: args.stage,
				connectors: args.connectors,
				caCertB64,
				edgeCertB64,
				edgeKeyB64,
				tailscaleAuthKey: authKey,
			}),
		);

	const composeUpload = new command.remote.CopyToRemote(
		`${args.name}-edge-compose`,
		{
			connection,
			remotePath: `${deploymentDirectory}/compose.yml`,
			source: new pulumi.asset.StringAsset(compose),
			triggers: [deploymentHash(compose)],
		},
		{ parent: args.parent, dependsOn: prepare },
	);

	const environmentUpload = new command.remote.CopyToRemote(
		`${args.name}-edge-environment`,
		{
			connection,
			remotePath: `${deploymentDirectory}/edge.env`,
			source: environment.apply((value) => new pulumi.asset.StringAsset(value)),
			triggers: [environment.apply((value) => deploymentHash(value))],
		},
		{ parent: args.parent, dependsOn: prepare },
	);

	const hash = pulumi
		.all([environment])
		.apply(([environmentValue]) => deploymentHash(compose, environmentValue));
	const deploy = new command.remote.Command(
		`${args.name}-edge-deploy`,
		{
			connection,
			create: deployCommand,
			update: deployCommand,
			triggers: [hash],
		},
		{ parent: args.parent, dependsOn: [composeUpload, environmentUpload] },
	);

	return {
		ipv4: droplet.ipv4Address,
		ipv6: droplet.ipv6Address,
		hostId: droplet.id,
		ready: deploy,
		statusCommand: pulumi.interpolate`ssh root@${droplet.ipv4Address} 'docker compose -f /opt/tailbridge/compose.yml ps'`,
		logsCommand: pulumi.interpolate`ssh root@${droplet.ipv4Address} 'docker compose -f /opt/tailbridge/compose.yml logs edge'`,
	};
}

function physicalName(stage: string, maximumLength = 63): string {
	const normalized = `tailbridge-${stage}`
		.toLowerCase()
		.replace(/[^a-z0-9-]/g, "-")
		.replace(/-+/g, "-")
		.replace(/^-|-$/g, "");
	return normalized.slice(0, maximumLength).replace(/-$/g, "");
}

function prepareCommand(volumeName: pulumi.Output<string>): pulumi.Output<string> {
	return volumeName.apply(
		(name) => `set -eu
cloud-init status --wait
device=/dev/disk/by-id/scsi-0DO_Volume_${name}
for attempt in $(seq 1 60); do
  test -b "$device" && break
  sleep 2
done
test -b "$device"
install -d -m 0700 ${stateDirectory}
if ! mountpoint -q ${stateDirectory}; then
  mount "$device" ${stateDirectory}
fi
if ! grep -Fq "LABEL=${volumeLabel} ${stateDirectory} ext4 defaults,nofail 0 2" /etc/fstab; then
  printf '%s\n' "LABEL=${volumeLabel} ${stateDirectory} ext4 defaults,nofail 0 2" >> /etc/fstab
fi
install -d -m 0700 ${stateDirectory}/tailscale ${deploymentDirectory}
`,
	);
}

const deployCommand = `set -eu
chmod 0600 ${deploymentDirectory}/edge.env
docker compose -f ${deploymentDirectory}/compose.yml pull
docker compose -f ${deploymentDirectory}/compose.yml up -d --remove-orphans
for attempt in $(seq 1 60); do
  if curl --fail --silent http://127.0.0.1:9090/healthz >/dev/null; then
    exit 0
  fi
  sleep 2
done
docker compose -f ${deploymentDirectory}/compose.yml logs --tail=100 edge
exit 1
`;
