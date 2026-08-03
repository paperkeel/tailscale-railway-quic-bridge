import * as pulumi from "@pulumi/pulumi";
import * as tls from "@pulumi/tls";

export interface ConnectorCertificate {
	certB64: pulumi.Output<string>;
	keyB64: pulumi.Output<string>;
}

export interface Certificates {
	caCertB64: pulumi.Output<string>;
	edgeCertB64: pulumi.Output<string>;
	edgeKeyB64: pulumi.Output<string>;
	connectors: ReadonlyMap<string, ConnectorCertificate>;
	sshPublicKey: pulumi.Output<string>;
	sshPrivateKey: pulumi.Output<string>;
}

export function createCertificates(
	name: string,
	edgeId: string,
	connectorIds: string[],
	opts?: pulumi.ComponentResourceOptions,
): Certificates {
	const caKey = new tls.PrivateKey(`${name}-ca-key`, {
		algorithm: "ED25519",
	}, opts);
	const ca = new tls.SelfSignedCert(`${name}-ca`, {
		privateKeyPem: caKey.privateKeyPem,
		isCaCertificate: true,
		validityPeriodHours: 24 * 365 * 10,
		earlyRenewalHours: 24 * 30,
		allowedUses: ["certSigning", "digitalSignature"],
		subject: { commonName: `Tailbridge ${edgeId} CA` },
	}, opts);

	const edge = createLeaf(
		`${name}-edge`,
		"edge",
		"serverAuth",
		edgeId,
		ca,
		caKey,
		opts,
	);
	const connectors = new Map<string, ConnectorCertificate>();
	for (const connectorId of connectorIds) {
		const leaf = createLeaf(
			`${name}-connector-${connectorId}`,
			"connector",
			"clientAuth",
			connectorId,
			ca,
			caKey,
			opts,
		);
		connectors.set(connectorId, {
			certB64: encodeBase64(leaf.certificate.certPem),
			keyB64: encodeBase64(leaf.key.privateKeyPemPkcs8),
		});
	}
	const ssh = new tls.PrivateKey(`${name}-edge-ssh-key`, {
		algorithm: "ED25519",
	}, opts);

	return {
		caCertB64: encodeBase64(ca.certPem),
		edgeCertB64: encodeBase64(edge.certificate.certPem),
		edgeKeyB64: encodeBase64(edge.key.privateKeyPemPkcs8),
		connectors,
		sshPublicKey: ssh.publicKeyOpenssh.apply((value) => value.trim()),
		sshPrivateKey: ssh.privateKeyOpenssh,
	};
}

function createLeaf(
	name: string,
	role: "edge" | "connector",
	usage: "serverAuth" | "clientAuth",
	identity: string,
	ca: tls.SelfSignedCert,
	caKey: tls.PrivateKey,
	opts?: pulumi.ComponentResourceOptions,
): { key: tls.PrivateKey; certificate: tls.LocallySignedCert } {
	const key = new tls.PrivateKey(`${name}-key`, { algorithm: "ED25519" }, opts);
	const request = new tls.CertRequest(`${name}-request`, {
		privateKeyPem: key.privateKeyPem,
		uris: [`spiffe://tailbridge.local/${role}/${identity}`],
		subject: { commonName: `tailbridge-${role}-${identity}` },
	}, opts);
	const certificate = new tls.LocallySignedCert(`${name}-certificate`, {
		certRequestPem: request.certRequestPem,
		caPrivateKeyPem: caKey.privateKeyPem,
		caCertPem: ca.certPem,
		validityPeriodHours: 24 * 90,
		earlyRenewalHours: 24 * 30,
		allowedUses: ["digitalSignature", usage],
	}, opts);
	return { key, certificate };
}

function encodeBase64(value: pulumi.Output<string>): pulumi.Output<string> {
	return value.apply((pem) => Buffer.from(pem, "utf8").toString("base64"));
}
