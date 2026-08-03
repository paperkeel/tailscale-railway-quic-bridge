import * as pulumi from "@pulumi/pulumi";
import * as railway from "@sst-provider/railway";

import type { NormalizedConnectorTarget } from "./config";
import { RailwayServiceSettings } from "./railway-settings";

export interface RailwayConnectorArgs {
	name: string;
	stage: string;
	edgeId: string;
	target: NormalizedConnectorTarget;
	connectorImage: string;
	edge: {
		ipv4: pulumi.Input<string>;
		ready: pulumi.Resource;
	};
	certificates: {
		caCertB64: pulumi.Input<string>;
		connectorCertB64: pulumi.Input<string>;
		connectorKeyB64: pulumi.Input<string>;
	};
	parent: pulumi.ComponentResource;
}

export interface RailwayConnectorOutputs {
	projectId: pulumi.Output<string>;
	environmentId: pulumi.Output<string>;
	serviceId: pulumi.Output<string>;
}

export function createRailwayConnector(
	args: RailwayConnectorArgs,
): RailwayConnectorOutputs {
	const { target } = args;
	const childOptions = { parent: args.parent };
	const projectId = pulumi.output(target.projectId);
	const environmentId = pulumi.output(target.environmentId);
	const resourceName = `${args.name}-connector-${target.slot}`;
	const service = new railway.Service(`${resourceName}-service`, {
		name: `tailbridge-${args.stage}-${target.name}`,
		projectId,
		sourceImage: args.connectorImage,
	}, childOptions);

	const settings = new RailwayServiceSettings(
		`${resourceName}-settings`,
		{
			environmentId,
			region: target.region,
			serviceId: service.id,
		},
		{ parent: args.parent, dependsOn: [args.edge.ready, service] },
	);

	new railway.VariableCollection(
		`${resourceName}-variables`,
		{
			environmentId,
			serviceId: service.id,
			variables: [
				{ name: "TB_CONNECTOR_ID", value: target.name },
				{ name: "TB_EDGE_ID", value: args.edgeId },
				{ name: "TB_ENVIRONMENT", value: args.stage },
				{
					name: "TB_EDGE_ENDPOINT",
					value: pulumi.interpolate`${args.edge.ipv4}:4433`,
				},
				{ name: "TB_VIRTUAL_PREFIX", value: target.virtualPrefix },
				{ name: "TB_REAL_PREFIX", value: target.realPrefix },
				{ name: "TB_DNS_SUFFIX", value: target.dnsSuffix },
				{ name: "TB_ALLOWED_DESTINATIONS", value: target.realPrefix },
				{ name: "TB_MTLS_CA_B64", value: args.certificates.caCertB64 },
				{
					name: "TB_MTLS_CERT_B64",
					value: args.certificates.connectorCertB64,
				},
				{
					name: "TB_MTLS_KEY_B64",
					value: args.certificates.connectorKeyB64,
				},
			],
		},
		{
			parent: args.parent,
			additionalSecretOutputs: ["variables"],
			dependsOn: settings,
		},
	);

	return { projectId, environmentId, serviceId: service.id };
}
