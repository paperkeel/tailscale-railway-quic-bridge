import type * as pulumi from "@pulumi/pulumi";

export interface EdgeCertificates {
	caCertB64: pulumi.Input<string>;
	edgeCertB64: pulumi.Input<string>;
	edgeKeyB64: pulumi.Input<string>;
	intermediateCertB64?: pulumi.Input<string>;
	intermediateKeyB64?: pulumi.Input<string>;
	sshPublicKey: pulumi.Input<string>;
	sshPrivateKey: pulumi.Input<string>;
}

export interface EdgeConnectorConfig {
	connectorId: string;
	projectId: pulumi.Input<string>;
	environment: pulumi.Input<string>;
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
	registration?: {
		frozen: boolean;
		newProjectsFrozen?: boolean;
		allowedProjectIds?: string[];
		virtualNetwork?: string;
		excludedPrefixes?: string[];
		oidcPolicies: pulumi.Input<unknown[]>;
		approvalTailscaleTags?: string[];
		edgeTailscaleTag?: string;
		leases?: { preview?: string; persistent?: string; quarantine?: string };
	};
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
