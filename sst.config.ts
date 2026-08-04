/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
	app() {
		const home = process.env.SST_HOME?.trim() || "cloudflare";
		if (home !== "cloudflare" && home !== "local") {
			throw new Error("SST_HOME must be cloudflare or local.");
		}
		return {
			name: "tailbridge",
			home,
			removal: "remove",
			providers: {
				command: { package: "@pulumi/command", version: "1.2.1" },
				digitalocean: {
					package: "@pulumi/digitalocean",
					version: "4.78.0",
				},
				railway: {
					package: "@sst-provider/railway",
					version: "0.6.1",
				},
				tls: { package: "@pulumi/tls", version: "5.5.1" },
			},
		};
	},
	async run() {
		const { Tailbridge } = await import("./infra");
		const projectId = required("RAILWAY_PROJECT_ID");
		const environmentId = required("RAILWAY_ENVIRONMENT_ID");
		const stage = $app.stage;
		const connectorName = process.env.TAILBRIDGE_CONNECTOR_ID?.trim() || stage;
		const edgeId = process.env.TAILBRIDGE_EDGE_ID?.trim() || connectorName;
		const image = process.env.TAILBRIDGE_IMAGE?.trim();
		const images = image
			? {
					edge: imageReference("edge", image),
					connector: imageReference("connector", image),
				}
			: undefined;
		const tailbridge = new Tailbridge("Tailbridge", {
			stage,
			edgeId,
			edge: {
				provider: "digitalocean",
				region: process.env.DIGITALOCEAN_REGION?.trim() || "nyc3",
				size: process.env.DIGITALOCEAN_SIZE?.trim() || "s-1vcpu-1gb",
				sshSourceCidrs: required("EDGE_SSH_SOURCE_CIDRS")
					.split(",")
					.map((cidr) => cidr.trim()),
			},
			connectors: [
				{
					name: connectorName,
					slot: 0,
					projectId,
					environmentId,
					region: process.env.RAILWAY_REGION?.trim() || "us-west2",
					realPrefix: process.env.TAILBRIDGE_ROUTES?.trim() || "fd12::/16",
				},
			],
			tailscaleAuthKey: new sst.Secret("TailscaleAuthKey").value,
			images,
		});

		return {
			artifactVersion: tailbridge.artifactVersion,
			edgeId: tailbridge.edgeId,
			edgeIpv4: tailbridge.edgeIpv4,
			edgeIpv6: tailbridge.edgeIpv6,
			connectorEndpoint: tailbridge.connectorEndpoint,
			connectors: tailbridge.connectors,
			tailscaleRoutes: tailbridge.tailscaleRoutes,
			tailscalePolicyFragment: tailbridge.tailscalePolicyFragment,
			edgeStatusCommand: tailbridge.edgeStatusCommand,
			edgeLogsCommand: tailbridge.edgeLogsCommand,
		};
	},
});

function required(name: string): string {
	const value = process.env[name]?.trim();
	if (!value) throw new Error(`${name} must be set.`);
	return value;
}

function imageReference(component: "edge" | "connector", image: string): string {
	const repository = `ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-${component}`;
	if (/^sha256:[0-9a-f]{64}$/.test(image)) {
		return `${repository}@${image}`;
	}
	if (/^sha-[0-9a-f]{40}$/.test(image)) {
		return `${repository}:${image}`;
	}
	throw new Error(
		"TAILBRIDGE_IMAGE must be a sha-<full-commit-sha> tag or a sha256 digest.",
	);
}
