import type * as pulumi from "@pulumi/pulumi";

export interface EdgeCertificates {
	caCertB64: pulumi.Input<string>;
	edgeCertB64: pulumi.Input<string>;
	edgeKeyB64: pulumi.Input<string>;
	sshPublicKey: pulumi.Input<string>;
	sshPrivateKey: pulumi.Input<string>;
}

export interface EdgeConnectorConfig {
	connectorId: string;
	environment: string;
	slot: number;
	virtualPrefix: string;
	realPrefix: string;
	dnsSuffix: string;
}

export interface EdgeDeploymentArgs {
	name: string;
	stage: string;
	edgeId: string;
	image: string;
	edge: {
		region: string;
		size: string;
		sshSourceCidrs: string[];
	};
	connectors: EdgeConnectorConfig[];
	certificates: EdgeCertificates;
	tailscaleAuthKey: pulumi.Input<string>;
	parent: pulumi.ComponentResource;
}

export interface EdgeDeployment {
	ipv4: pulumi.Output<string>;
	ipv6: pulumi.Output<string>;
	hostId: pulumi.Output<string>;
	ready: pulumi.Resource;
	statusCommand: pulumi.Output<string>;
	logsCommand: pulumi.Output<string>;
}

export interface EdgeProvider {
	deploy(args: EdgeDeploymentArgs): EdgeDeployment;
}
