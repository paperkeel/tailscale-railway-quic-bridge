import { describe, expect, it } from "vitest";

import {
	deploymentHash,
	loadComposeTemplate,
	renderCloudInit,
	renderCompose,
	renderEdgeEnvironment,
	edgeImageReference,
} from "./runtime";

describe("edge runtime rendering", () => {
	it("keeps credentials out of cloud-init", () => {
		const cloudInit = renderCloudInit();

		expect(cloudInit).toContain("docker-compose-v2");
		expect(cloudInit).toContain("net.ipv4.ip_forward=1");
		expect(cloudInit).not.toMatch(/AUTHKEY|MTLS|PRIVATE KEY|edge\.env/i);
		expect(cloudInit).not.toMatch(/secret-(ca|cert|key|token)/i);
	});

	it("renders the edge environment with a final newline", () => {
		const environment = renderEdgeEnvironment({
			edgeId: "shared-edge",
			environment: "production",
			connectors: [connector("api", 0, "fd20::/16")],
			caCertB64: "ca",
			edgeCertB64: "cert",
			edgeKeyB64: "key",
			tailscaleAuthKey: "tskey-auth-test",
		});

		expect(environment).toContain("TB_EDGE_ID=shared-edge\n");
		expect(environment).toContain("TB_MTLS_KEY_B64=key\n");
		expect(environment).toContain("TB_ALLOWED_ROUTES=fd20::/16\n");
		const encoded = environment.match(/^TB_CONNECTORS_B64=(.+)$/m)?.[1];
		expect(JSON.parse(Buffer.from(encoded ?? "", "base64").toString())).toEqual([
			connector("api", 0, "fd20::/16"),
		]);
		expect(environment).toContain("TS_AUTHKEY=tskey-auth-test\n");
		expect(environment).toContain("TS_STATE_DIR=/var/lib/tailscale\n");
		expect(environment.endsWith("\n")).toBe(true);
	});

	it("rejects multiline environment values", () => {
		expect(() =>
			renderEdgeEnvironment({
				edgeId: "edge\ninjected=value",
				environment: "production",
				connectors: [connector("api", 0, "fd20::/16")],
				caCertB64: "ca",
				edgeCertB64: "cert",
				edgeKeyB64: "key",
				tailscaleAuthKey: "auth",
			}),
		).toThrow("must not contain newlines");
	});

	it("renders image tags, digests, and full references", () => {
		const template = "image: {{EDGE_IMAGE}}\n";

		expect(renderCompose("internal-testing", template)).toBe(
			"image: ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-edge:internal-testing\n",
		);
		const digest = `sha256:${"a".repeat(64)}`;
		expect(renderCompose(digest, template)).toContain(`@${digest}`);
		expect(renderCompose("registry.example/edge:v1", template)).toBe(
			"image: registry.example/edge:v1\n",
		);
		expect(renderCompose("tailbridge-edge:test", template)).toBe(
			"image: tailbridge-edge:test\n",
		);
	});

	it("rejects mutable and malformed edge image references", () => {
		expect(() => edgeImageReference("latest")).toThrow("latest tag");
		expect(() => edgeImageReference("registry.example/edge:latest")).toThrow(
			"latest tag",
		);
		expect(() => edgeImageReference("registry.example/edge")).toThrow(
			"tag or digest",
		);
		expect(() => edgeImageReference("sha256:abc")).toThrow(
			"complete SHA-256 digest",
		);
		expect(() => edgeImageReference("edge tag")).toThrow("whitespace");
	});

	it("binds the persistent Tailscale state into the edge container", () => {
		const compose = loadComposeTemplate();

		expect(compose).toContain(
			"/var/lib/tailbridge/tailscale:/var/lib/tailscale",
		);
		expect(compose).toContain("read_only: true");
		expect(compose).toContain("NET_ADMIN");
		expect(compose).toContain("NET_RAW");
		expect(compose).not.toContain("SYS_ADMIN");
		expect(compose).not.toMatch(/^\s+connector:/m);
	});

	it("uses content boundaries in deployment hashes", () => {
		expect(deploymentHash("ab", "c")).not.toBe(deploymentHash("a", "bc"));
		expect(deploymentHash("ab", "c")).toBe(deploymentHash("ab", "c"));
	});
});

function connector(name: string, slot: number, virtualPrefix: string) {
	return {
		connectorId: name,
		environment: "production",
		slot,
		virtualPrefix,
		realPrefix: "fd12::/16",
		dnsSuffix: `${name}.railway.internal`,
	};
}
