import * as pulumi from "@pulumi/pulumi";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { NormalizedConnectorTarget } from "./config";
import { createRailwayConnector } from "./railway";
import { requestRailwayGraphql } from "./railway-settings";

const resources: pulumi.runtime.MockResourceArgs[] = [];

beforeAll(() => {
	pulumi.runtime.setMocks(
		{
			newResource: (args) => {
				resources.push(args);
				return { id: `${args.name}-id`, state: args.inputs };
			},
			call: (args) => args.inputs,
		},
		"tailbridge",
		"test",
		false,
	);
});

describe("createRailwayConnector", () => {
	it("creates one isolated service and variable collection for a target", async () => {
		const parent = new pulumi.ComponentResource(
			"tailbridge:index:Tailbridge",
			"Tailbridge",
		);
		const ready = new pulumi.ComponentResource(
			"tailbridge:test:EdgeReady",
			"edge-ready",
		);
		const outputs = createRailwayConnector({
			name: "Tailbridge",
			stage: "test",
			edgeId: "shared-edge",
			target,
			connectorImage: "registry.example/connector@sha256:0123",
			edge: { ipv4: "192.0.2.10", ready },
			certificates: {
				caCertB64: pulumi.secret("ca"),
				connectorCertB64: pulumi.secret("certificate"),
				connectorKeyB64: pulumi.secret("private-key"),
			},
			parent,
		});

		await resolve(outputs.serviceId);
		await vi.waitFor(() => {
			expect(
				resources.some(
					(candidate) => candidate.name === "Tailbridge-connector-0-variables",
				),
			).toBe(true);
		});
		const service = resource("railway:index/service:Service");
		expect(service.inputs).toMatchObject({
			name: "tailbridge-test-api",
			projectId: "project-existing",
			sourceImage: "registry.example/connector@sha256:0123",
		});
		const variables = resourceByName(
			"Tailbridge-connector-0-variables",
		);
		const serialized = JSON.stringify(variables.inputs.variables);
		for (const value of [
			"TB_EDGE_ID",
			"TB_ENVIRONMENT",
			"environment-existing",
			"TB_VIRTUAL_PREFIX",
			"fd20::/16",
			"TB_REAL_PREFIX",
			"fd12::/16",
			"TB_DNS_SUFFIX",
			"api.railway.internal",
		]) {
			expect(serialized).toContain(value);
		}
	});
});

describe("requestRailwayGraphql", () => {
	it("rejects HTTP failures without exposing the token", async () => {
		const request = vi.fn<typeof fetch>().mockResolvedValue(
			new Response("{}", {
				status: 503,
				headers: { "Content-Type": "application/json" },
			}),
		);
		const result = requestRailwayGraphql(
			"query TailbridgeTest { me { id } }",
			{},
			"secret-token",
			request,
		);
		await expect(result).rejects.toThrow(
			"Railway GraphQL request failed (503).",
		);
		await expect(result).rejects.not.toThrow("secret-token");
	});

	it("rejects successful responses that contain GraphQL errors", async () => {
		const request = vi.fn<typeof fetch>().mockResolvedValue(
			new Response(
				JSON.stringify({ errors: [{ message: "Environment not found" }] }),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);
		await expect(
			requestRailwayGraphql(
				"mutation TailbridgeTest { test }",
				{},
				"secret-token",
				request,
			),
		).rejects.toThrow(
			"Railway GraphQL request failed (200): Environment not found",
		);
	});

	it("rejects a non-JSON response and sets a request timeout", async () => {
		const request = vi.fn<typeof fetch>().mockResolvedValue(
			new Response("upstream unavailable", { status: 502 }),
		);
		await expect(
			requestRailwayGraphql("query TailbridgeTest { me { id } }", {}, "token", request),
		).rejects.toThrow(
			"Railway GraphQL request failed (502): The response was not valid JSON.",
		);
		expect(request.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
	});

	it("returns false fields for callers to interpret", async () => {
		const request = vi.fn<typeof fetch>().mockResolvedValue(
			new Response(JSON.stringify({ data: { serviceInstanceUpdate: false } }), {
				status: 200,
			}),
		);
		await expect(
			requestRailwayGraphql("mutation TailbridgeTest { test }", {}, "token", request),
		).resolves.toEqual({ serviceInstanceUpdate: false });
	});
});

const target: NormalizedConnectorTarget = {
	name: "api",
	slot: 0,
	projectId: "project-existing",
	environmentId: "environment-existing",
	region: "us-west2",
	realPrefix: "fd12::/16",
	virtualPrefix: "fd20::/16",
	dnsSuffix: "api.railway.internal",
	nameserver: "fd20::10",
};

function resource(type: string): pulumi.runtime.MockResourceArgs {
	const match = resources.find((candidate) => candidate.type === type);
	if (!match) throw new Error(`Test resource ${type} does not exist.`);
	return match;
}

function resourceByName(name: string): pulumi.runtime.MockResourceArgs {
	const match = resources.find((candidate) => candidate.name === name);
	if (!match) throw new Error(`Test resource ${name} does not exist.`);
	return match;
}

function resolve<T>(output: pulumi.Output<T>): Promise<T> {
	return new Promise((resolveValue) => output.apply(resolveValue));
}
