import * as pulumi from "@pulumi/pulumi";
import { beforeAll, describe, expect, it } from "vitest";

import {
	createDigitalOceanEdge,
	edgeFirewallRules,
	edgeVolumeResourceOptions,
	prepareScript,
} from "./digitalocean";

const resources: pulumi.runtime.MockResourceArgs[] = [];
let operatorOutputs:
	| {
			statusCommand: string;
			logsCommand: string;
			statusIsSecret: boolean;
			logsIsSecret: boolean;
	  }
	| undefined;

beforeAll(async () => {
	pulumi.runtime.setMocks(
		{
			newResource: (args) => {
				resources.push(args);
				const state = { ...args.inputs };
				if (args.type === "digitalocean:index/droplet:Droplet") {
					Object.assign(state, {
						ipv4Address: "203.0.113.10",
						ipv6Address: "2001:db8::10",
					});
				}
				if (args.type === "digitalocean:index/sshKey:SshKey") {
					Object.assign(state, { fingerprint: "test-fingerprint" });
				}
				return { id: `${args.name}-id`, state };
			},
			call: (args) => args.inputs,
		},
		"tailbridge",
		"test",
		false,
	);

	const outputs = await pulumi.runtime.runInPulumiStack(async () => {
		const parent = new pulumi.ComponentResource(
			"tailbridge:index:Tailbridge",
			"Tailbridge",
		);
		const deployment = createDigitalOceanEdge({
			name: "Tailbridge",
			stage: "test",
			edgeId: "shared-edge",
			image: "tailbridge-edge:test",
			edge: {
				region: "nyc3",
				size: "s-1vcpu-1gb",
				sshSourceCidrs: ["192.0.2.0/24"],
			},
			connectors: [
				{
					connectorId: "api",
					environment: "test",
					slot: 0,
					virtualPrefix: "fd20::/16",
					realPrefix: "fd12::/16",
					dnsSuffix: "api.railway.internal",
				},
			],
			certificates: {
				caCertB64: pulumi.secret("secret-ca"),
				edgeCertB64: pulumi.secret("secret-cert"),
				edgeKeyB64: pulumi.secret("secret-edge-key"),
				sshPublicKey: "ssh-ed25519 public-key",
				sshPrivateKey: pulumi.secret("secret-ssh-key"),
			},
			tailscaleAuthKey: pulumi.secret("secret-tailscale-key"),
			parent,
		});

		return {
			statusCommand: await resolve(deployment.statusCommand),
			logsCommand: await resolve(deployment.logsCommand),
			statusIsSecret: await pulumi.isSecret(deployment.statusCommand),
			logsIsSecret: await pulumi.isSecret(deployment.logsCommand),
		};
	});
	if (!outputs) {
		throw new Error("The Pulumi test stack did not return edge outputs.");
	}
	operatorOutputs = {
		statusCommand: String(outputs.statusCommand),
		logsCommand: String(outputs.logsCommand),
		statusIsSecret: Boolean(outputs.statusIsSecret),
		logsIsSecret: Boolean(outputs.logsIsSecret),
	};
});

describe("DigitalOcean edge structure", () => {
	it("restricts SSH and opens only the two public UDP ports", () => {
		const rules = edgeFirewallRules(["192.0.2.0/24"]);

		expect(rules.inboundRules).toEqual([
			{
				protocol: "tcp",
				portRange: "22",
				sourceAddresses: ["192.0.2.0/24"],
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
		]);
	});

	it("creates and retains a persistent ext4 state volume", () => {
		const volume = resource("digitalocean:index/volume:Volume");
		const attachment = resource(
			"digitalocean:index/volumeAttachment:VolumeAttachment",
		);

		expect(volume.inputs).toMatchObject({
			size: 10,
			initialFilesystemType: "ext4",
			initialFilesystemLabel: "tailbridge",
		});
		expect(attachment.inputs.volumeId).toBe("Tailbridge-edge-state-id");
		expect(edgeVolumeResourceOptions).toEqual({ retainOnDelete: true });
	});

	it("preserves an existing secret environment until the atomic upload", () => {
		expect(prepareScript("tailbridge-state")).toContain(
			"chmod 0600 /opt/tailbridge/edge.env",
		);
		expect(prepareScript("tailbridge-state")).not.toContain(
			"/dev/null /opt/tailbridge/edge.env",
		);
	});

	it("returns workstation SSH commands without secret taint", () => {
		if (!operatorOutputs) {
			throw new Error("The Pulumi test stack did not return edge outputs.");
		}

		expect(operatorOutputs.statusCommand).toBe(
			"ssh root@203.0.113.10 'docker compose -f /opt/tailbridge/compose.yml ps'",
		);
		expect(operatorOutputs.logsCommand).toContain("ssh root@203.0.113.10");
		expect(operatorOutputs.statusIsSecret).toBe(false);
		expect(operatorOutputs.logsIsSecret).toBe(false);
		expect(JSON.stringify(operatorOutputs)).not.toMatch(
			/secret-(ca|cert|edge-key|ssh-key|tailscale-key)/,
		);
	});
});

function resource(type: string): pulumi.runtime.MockResourceArgs {
	const match = resources.find((candidate) => candidate.type === type);
	if (!match) {
		throw new Error(`Test resource ${type} does not exist.`);
	}
	return match;
}

function resolve(output: pulumi.Output<string>): Promise<string> {
	return new Promise((resolveValue) => {
		output.apply((value) => {
			resolveValue(value);
			return value;
		});
	});
}
