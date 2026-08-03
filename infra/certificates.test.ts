import * as pulumi from "@pulumi/pulumi";
import { beforeAll, describe, expect, it } from "vitest";

import { createCertificates } from "./certificates";

const resources: pulumi.runtime.MockResourceArgs[] = [];

beforeAll(() => {
	pulumi.runtime.setMocks(
		{
			newResource: (args) => {
				resources.push(args);
				const state = { ...args.inputs };
				if (args.type === "tls:index/privateKey:PrivateKey") {
					Object.assign(state, {
						privateKeyPem: "PRIVATE KEY PEM",
						privateKeyPemPkcs8: "PRIVATE KEY PKCS8",
						privateKeyOpenssh: "OPENSSH PRIVATE KEY",
						publicKeyOpenssh: "ssh-ed25519 public-key\n",
					});
				}
				if (
					args.type === "tls:index/selfSignedCert:SelfSignedCert" ||
					args.type === "tls:index/locallySignedCert:LocallySignedCert"
				) {
					Object.assign(state, { certPem: `${args.name} CERTIFICATE` });
				}
				if (args.type === "tls:index/certRequest:CertRequest") {
					Object.assign(state, { certRequestPem: `${args.name} REQUEST` });
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

describe("createCertificates", () => {
	it("creates role-specific TLS credentials and an SSH key", async () => {
		const outputs = await pulumi.runtime.runInPulumiStack(async () => {
			const certificates = createCertificates(
				"Tailbridge",
				"shared-edge",
				["api", "admin"],
			);
			const api = certificates.connectors.get("api");
			if (!api) throw new Error("The API certificate does not exist.");
			return {
				caCertB64: await resolve(certificates.caCertB64),
				edgeCertB64: await resolve(certificates.edgeCertB64),
				edgeKeyB64: await resolve(certificates.edgeKeyB64),
				connectorCertB64: await resolve(api.certB64),
				sshPublicKey: await resolve(certificates.sshPublicKey),
			};
		});
		if (!outputs) {
			throw new Error(
				"The Pulumi test stack did not return certificate outputs.",
			);
		}

		expect(Buffer.from(outputs.caCertB64, "base64").toString()).toBe(
			"Tailbridge-ca CERTIFICATE",
		);
		expect(Buffer.from(outputs.edgeKeyB64, "base64").toString()).toBe(
			"PRIVATE KEY PKCS8",
		);
		expect(outputs.sshPublicKey).toBe("ssh-ed25519 public-key");

		const ca = resource("Tailbridge-ca");
		expect(ca.inputs).toMatchObject({
			isCaCertificate: true,
			validityPeriodHours: 87_600,
			earlyRenewalHours: 720,
			allowedUses: ["certSigning", "digitalSignature"],
		});

		const edgeRequest = resource("Tailbridge-edge-request");
		expect(edgeRequest.inputs).toMatchObject({
			uris: ["spiffe://tailbridge.local/edge/shared-edge"],
		});
		const connectorRequest = resource("Tailbridge-connector-api-request");
		expect(connectorRequest.inputs).toMatchObject({
			uris: ["spiffe://tailbridge.local/connector/api"],
		});
		expect(resource("Tailbridge-connector-admin-request").inputs).toMatchObject({
			uris: ["spiffe://tailbridge.local/connector/admin"],
		});

		const edgeCertificate = resource("Tailbridge-edge-certificate");
		expect(edgeCertificate.inputs).toMatchObject({
			validityPeriodHours: 2_160,
			earlyRenewalHours: 720,
			allowedUses: ["digitalSignature", "serverAuth"],
		});
		const connectorCertificate = resource("Tailbridge-connector-api-certificate");
		expect(connectorCertificate.inputs).toMatchObject({
			allowedUses: ["digitalSignature", "clientAuth"],
		});
	});
});

function resource(name: string): pulumi.runtime.MockResourceArgs {
	const match = resources.find((candidate) => candidate.name === name);
	if (!match) {
		throw new Error(`Test resource ${name} does not exist.`);
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
