import { describe, expect, it } from "vitest";

import { normalizeTailbridgeArgs, parseHome } from "./config";
import type { TailbridgeArgs } from "./tailbridge";

describe("parseHome", () => {
	it("uses Cloudflare by default and accepts local state", () => {
		expect(parseHome(undefined)).toBe("cloudflare");
		expect(parseHome(" local ")).toBe("local");
	});

	it("rejects unsupported homes", () => {
		expect(() => parseHome("aws")).toThrow(
			"SST_HOME must be cloudflare or local.",
		);
	});
});

describe("normalizeTailbridgeArgs", () => {
	it("allocates stable connector networks and DNS settings", () => {
		const normalized = normalizeTailbridgeArgs(
			args([
				{ name: "api", slot: 0 },
				{ name: "admin", slot: 31, realPrefix: "fd55::/16" },
			]),
		);

		expect(normalized.virtualNetwork).toBe("fd20::/11");
		expect(normalized.connectors).toMatchObject([
			{
				name: "api",
				virtualPrefix: "fd20::/16",
				realPrefix: "fd12::/16",
				dnsSuffix: "api.railway.internal",
				nameserver: "fd20::10",
				region: "us-west2",
			},
			{
				name: "admin",
				virtualPrefix: "fd3f::/16",
				realPrefix: "fd55::/16",
				nameserver: "fd3f::10",
			},
		]);
	});

	it("canonicalizes equivalent virtual network spellings", () => {
		const normalized = normalizeTailbridgeArgs({
			...args([{ name: "api", slot: 0 }]),
			virtualNetwork: "fd20:0::/11",
		});
		expect(normalized.virtualNetwork).toBe("fd20::/11");
	});

	it.each([
		[
			args([
				{ name: "api", slot: 0 },
				{ name: "api", slot: 1 },
			]),
			"connector name api must be unique.",
		],
		[
			args([
				{ name: "api", slot: 0 },
				{ name: "admin", slot: 0 },
			]),
			"connector slot 0 must be unique.",
		],
		[args([{ name: "api", slot: 32 }]), "slot must be an integer"],
		[
			{ ...args([{ name: "api", slot: 0 }]), virtualNetwork: "fd20::/12" },
			"IPv6 /11",
		],
		[args([]), "at least one target"],
	])("rejects invalid component arguments", (input, message) => {
		expect(() => normalizeTailbridgeArgs(input)).toThrow(message);
	});
});

function args(
	connectors: Array<{ name: string; slot: number; realPrefix?: string }>,
): TailbridgeArgs {
	return {
		stage: "test",
		edgeId: "shared-edge",
		edge: {
			provider: "digitalocean",
			region: "nyc3",
			size: "s-1vcpu-1gb",
			sshSourceCidrs: ["192.0.2.0/24"],
		},
		connectors: connectors.map((connector) => ({
			...connector,
			projectId: `${connector.name}-project`,
			environmentId: `${connector.name}-environment`,
		})),
		tailscaleAuthKey: "test-key",
	};
}
