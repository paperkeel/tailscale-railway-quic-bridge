import * as pulumi from "@pulumi/pulumi";
import { beforeAll, describe, expect, it } from "vitest";

import { Tailbridge } from "./tailbridge";

const resources: pulumi.runtime.MockResourceArgs[] = [];

beforeAll(() => {
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
				if (args.type === "tls:index/privateKey:PrivateKey") {
					Object.assign(state, {
						privateKeyPem: "PRIVATE KEY PEM",
						privateKeyPemPkcs8: "PRIVATE KEY PKCS8",
						privateKeyOpenssh: "OPENSSH PRIVATE KEY",
						publicKeyOpenssh: "ssh-ed25519 public-key",
					});
				}
				if (args.type.endsWith("Cert:SelfSignedCert")) {
					Object.assign(state, { certPem: "CA CERTIFICATE" });
				}
				if (args.type.endsWith("Cert:LocallySignedCert")) {
					Object.assign(state, { certPem: "LEAF CERTIFICATE" });
				}
				if (args.type === "tls:index/certRequest:CertRequest") {
					Object.assign(state, { certRequestPem: "CERTIFICATE REQUEST" });
				}
				return { id: `${args.name}-id`, state };
			},
			call: (args) => args.inputs,
		},
		"tailbridge",
		"test",
		false,
	);
});

describe("Tailbridge", () => {
	it("rejects a virtual network that the data plane does not support", () => {
		expect(
			() =>
				new Tailbridge("UnsupportedNetwork", {
					stage: "test",
					edgeId: "shared-edge",
					virtualNetwork: "fd40::/11",
					edge: {
						provider: "digitalocean",
						region: "nyc3",
						size: "s-1vcpu-1gb",
						sshSourceCidrs: ["192.0.2.0/24"],
					},
					connectors: [
						{
							name: "api",
							slot: 0,
							projectId: "api-project",
							environmentId: "api-environment",
						},
					],
					tailscaleAuthKey: pulumi.secret("secret-auth-key"),
				}),
		).toThrow(
			"virtualNetwork must be fd20::/11 until the data plane supports other networks.",
		);
	});

	it("rejects a development package in a production stage", () => {
		expect(
			() =>
				new Tailbridge("Production", {
					stage: "production",
					edgeId: "shared-edge",
					edge: {
						provider: "digitalocean",
						region: "nyc3",
						size: "s-1vcpu-1gb",
						sshSourceCidrs: ["192.0.2.0/24"],
					},
					connectors: [
						{
							name: "api",
							slot: 0,
							projectId: "api-project",
							environmentId: "api-environment",
						},
					],
					tailscaleAuthKey: pulumi.secret("secret-auth-key"),
					images: {
						edge: `example.com/edge@sha256:${"a".repeat(64)}`,
						connector: `example.com/connector@sha256:${"b".repeat(64)}`,
					},
				}),
		).toThrow(
			"A development package cannot deploy outside a development or test stage.",
		);
	});

	it("creates one edge and exposes safe outputs for multiple targets", async () => {
		const outputs = await pulumi.runtime.runInPulumiStack(async () => {
			const tailbridge = new Tailbridge("Tailbridge", {
				stage: "test",
				edgeId: "shared-edge",
				edge: {
					provider: "digitalocean",
					region: "nyc3",
					size: "s-1vcpu-1gb",
					sshSourceCidrs: ["192.0.2.0/24"],
				},
				connectors: [
					{
						name: "api",
						slot: 0,
						projectId: "api-project",
						environmentId: "api-environment",
					},
					{
						name: "admin",
						slot: 1,
						projectId: "admin-project",
						environmentId: "admin-environment",
					},
				],
				tailscaleAuthKey: pulumi.secret("secret-auth-key"),
			});
			return {
				artifactVersion: await resolve(tailbridge.artifactVersion),
				connectors: await resolve(tailbridge.connectors),
				routes: await resolve(tailbridge.tailscaleRoutes),
				status: await resolve(tailbridge.edgeStatusCommand),
				statusIsSecret: await pulumi.isSecret(tailbridge.edgeStatusCommand),
			};
		});

		expect(outputs?.artifactVersion).toBe("0.0.0-development");
		expect(outputs?.routes).toEqual(["fd20::/16", "fd21::/16"]);
		expect(outputs?.connectors).toMatchObject([
			{ name: "api", nameserver: "fd20::10" },
			{ name: "admin", nameserver: "fd21::10" },
		]);
		expect(outputs?.statusIsSecret).toBe(false);
		expect(JSON.stringify(outputs)).not.toContain("secret-auth-key");
		expect(
			resources.filter(
				(resource) => resource.type === "digitalocean:index/droplet:Droplet",
			),
		).toHaveLength(1);
		expect(
			resources.filter(
				(resource) => resource.type === "railway:index/service:Service",
			),
		).toHaveLength(2);
	});
});

function resolve<T>(output: pulumi.Output<T>): Promise<T> {
	return new Promise((resolveValue) => output.apply(resolveValue));
}
