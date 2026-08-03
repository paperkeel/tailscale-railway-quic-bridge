import * as pulumi from "@pulumi/pulumi";

import { tailbridgeBuild, type TailbridgeBuild } from "./build";
import { createCertificates } from "./certificates";
import { normalizeTailbridgeArgs } from "./config";
import { createDigitalOceanEdge } from "./edge/digitalocean";
import { createRailwayConnector } from "./railway";

export interface TailbridgeConnectorTarget {
	name: string;
	slot: number;
	projectId: pulumi.Input<string>;
	environmentId: pulumi.Input<string>;
	region?: string;
	realPrefix?: string;
}

export interface TailbridgeArgs {
	stage: string;
	edgeId: string;
	virtualNetwork?: string;
	edge: {
		provider: "digitalocean";
		region: string;
		size: string;
		sshSourceCidrs: string[];
	};
	connectors: TailbridgeConnectorTarget[];
	tailscaleAuthKey: pulumi.Input<string>;
	images?: {
		edge?: string;
		connector?: string;
	};
}

export interface TailbridgeConnectorOutput {
	name: string;
	slot: number;
	virtualPrefix: string;
	dnsSuffix: string;
	nameserver: string;
	railwayProjectId: string;
	railwayEnvironmentId: string;
	railwayServiceId: string;
}

export interface TailscalePolicyFragment {
	tagOwners: Record<string, string[]>;
	autoApprovers: { routes: Record<string, string[]> };
}

export class Tailbridge extends pulumi.ComponentResource {
	public readonly artifactVersion: pulumi.Output<string>;
	public readonly edgeId: pulumi.Output<string>;
	public readonly edgeIpv4: pulumi.Output<string>;
	public readonly edgeIpv6: pulumi.Output<string>;
	public readonly connectorEndpoint: pulumi.Output<string>;
	public readonly connectors: pulumi.Output<TailbridgeConnectorOutput[]>;
	public readonly tailscaleRoutes: pulumi.Output<string[]>;
	public readonly tailscalePolicyFragment: pulumi.Output<TailscalePolicyFragment>;
	public readonly edgeStatusCommand: pulumi.Output<string>;
	public readonly edgeLogsCommand: pulumi.Output<string>;

	constructor(
		name: string,
		args: TailbridgeArgs,
		opts?: pulumi.ComponentResourceOptions,
	) {
		super("tailbridge:index:Tailbridge", name, {}, opts);
		const normalized = normalizeTailbridgeArgs(args);
		if (normalized.virtualNetwork !== "fd20::/11") {
			throw new Error(
				"virtualNetwork must be fd20::/11 until the data plane supports other networks.",
			);
		}
		const images = resolveImages(normalized.stage, normalized.images);
		const certificates = createCertificates(
			name,
			normalized.edgeId,
			normalized.connectors.map((target) => target.name),
			{ parent: this },
		);
		const edge = createDigitalOceanEdge({
			name,
			stage: normalized.stage,
			edgeId: normalized.edgeId,
			image: images.edge,
			edge: normalized.edge,
			connectors: normalized.connectors.map((target) => ({
				connectorId: target.name,
				environment: target.environmentId,
				slot: target.slot,
				virtualPrefix: target.virtualPrefix,
				realPrefix: target.realPrefix,
				dnsSuffix: target.dnsSuffix,
			})),
			certificates,
			tailscaleAuthKey: normalized.tailscaleAuthKey,
			parent: this,
		});
		const connectorResources = normalized.connectors.map((target) => {
			const connectorCertificate = certificates.connectors.get(target.name);
			if (!connectorCertificate) {
				throw new Error(`connector ${target.name} certificate does not exist.`);
			}
			return {
				target,
				outputs: createRailwayConnector({
					name,
					stage: normalized.stage,
					edgeId: normalized.edgeId,
					target,
					connectorImage: images.connector,
					edge,
					certificates: {
						caCertB64: certificates.caCertB64,
						connectorCertB64: connectorCertificate.certB64,
						connectorKeyB64: connectorCertificate.keyB64,
					},
					parent: this,
				}),
			};
		});

		this.artifactVersion = pulumi.output(tailbridgeBuild.packageVersion);
		this.edgeId = pulumi.output(normalized.edgeId);
		this.edgeIpv4 = edge.ipv4;
		this.edgeIpv6 = edge.ipv6;
		this.connectorEndpoint = pulumi.interpolate`${edge.ipv4}:4433`;
		this.connectors = pulumi
			.all(
				connectorResources.map(({ target, outputs }) =>
					pulumi
						.all([outputs.projectId, outputs.environmentId, outputs.serviceId])
						.apply(([projectId, environmentId, serviceId]) => ({
							name: target.name,
							slot: target.slot,
							virtualPrefix: target.virtualPrefix,
							dnsSuffix: target.dnsSuffix,
							nameserver: target.nameserver,
							railwayProjectId: projectId,
							railwayEnvironmentId: environmentId,
							railwayServiceId: serviceId,
						})),
				),
			)
			.apply((connectors) => [...connectors]);
		this.tailscaleRoutes = pulumi.output(
			normalized.connectors.map((target) => target.virtualPrefix),
		);
		this.tailscalePolicyFragment = this.tailscaleRoutes.apply((routes) => {
			const fragment: TailscalePolicyFragment = {
				tagOwners: { "tag:tailbridge": ["autogroup:admin"] },
				autoApprovers: {
					routes: Object.fromEntries(
						routes.map((route) => [route, ["tag:tailbridge"]]),
					),
				},
			};
			return fragment;
		});
		this.edgeStatusCommand = edge.statusCommand;
		this.edgeLogsCommand = edge.logsCommand;

		this.registerOutputs({
			artifactVersion: this.artifactVersion,
			edgeId: this.edgeId,
			edgeIpv4: this.edgeIpv4,
			edgeIpv6: this.edgeIpv6,
			connectorEndpoint: this.connectorEndpoint,
			connectors: this.connectors,
			tailscaleRoutes: this.tailscaleRoutes,
			tailscalePolicyFragment: this.tailscalePolicyFragment,
			edgeStatusCommand: this.edgeStatusCommand,
			edgeLogsCommand: this.edgeLogsCommand,
		});
	}
}

function resolveImages(
	stage: string,
	overrides: TailbridgeArgs["images"],
): { edge: string; connector: string } {
	const images = {
		edge: overrides?.edge ?? tailbridgeBuild.edgeImage,
		connector: overrides?.connector ?? tailbridgeBuild.connectorImage,
	};
	if (tailbridgeBuild.sourceCommit === "development" && !isDevelopmentStage(stage)) {
		throw new Error(
			"A development package cannot deploy outside a development or test stage.",
		);
	}
	if (!isDevelopmentStage(stage)) {
		validateImmutableImage("edge", images.edge);
		validateImmutableImage("connector", images.connector);
	}
	return images;
}

function validateImmutableImage(component: string, image: string): void {
	const digest = /@sha256:[a-f0-9]{64}$/;
	const commitTag = /:sha-[a-f0-9]{40}$/;
	if (!digest.test(image) && !commitTag.test(image)) {
		throw new Error(
			`${component} image must use a SHA-256 digest or a full commit SHA tag.`,
		);
	}
}

function isDevelopmentStage(stage: string): boolean {
	return /^(development|dev|test)(-|$)/.test(stage);
}

export { tailbridgeBuild };
export type { TailbridgeBuild };
