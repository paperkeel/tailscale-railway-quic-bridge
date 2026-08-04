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
	intermediateCertB64: pulumi.Output<string>;
	intermediateKeyB64: pulumi.Output<string>;
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
	const caKey = new tls.PrivateKey(
		`${name}-ca-key`,
		{
			algorithm: "ED25519",
		},
		opts,
	);
	const ca = new tls.SelfSignedCert(
		`${name}-ca`,
		{
			privateKeyPem: caKey.privateKeyPem,
			isCaCertificate: true,
			validityPeriodHours: 24 * 365,
			allowedUses: ["cert_signing", "digital_signature"],
			subject: { commonName: `Tailbridge ${edgeId} CA` },
		},
		opts,
	);

	const edge = createLeaf(
		`${name}-edge`,
		"edge",
		"server_auth",
		edgeId,
		ca,
		caKey,
		opts,
	);
	const intermediateKey = new tls.PrivateKey(
		`${name}-online-ca-key`,
		{ algorithm: "ED25519" },
		opts,
	);
	const intermediateRequest = new tls.CertRequest(
		`${name}-online-ca-request`,
		{
			privateKeyPem: intermediateKey.privateKeyPem,
			subject: { commonName: `Tailbridge ${edgeId} online CA` },
		},
		opts,
	);
	const intermediate = new tls.LocallySignedCert(
		`${name}-online-ca-certificate`,
		{
			certRequestPem: intermediateRequest.certRequestPem,
			caPrivateKeyPem: caKey.privateKeyPem,
			caCertPem: ca.certPem,
			isCaCertificate: true,
			validityPeriodHours: 24 * 30,
			earlyRenewalHours: 24 * 7,
			allowedUses: ["cert_signing", "digital_signature"],
		},
		opts,
	);
	const connectors = new Map<string, ConnectorCertificate>();
	for (const connectorId of connectorIds) {
		const leaf = createLeaf(
			`${name}-connector-${connectorId}`,
			"connector",
			"client_auth",
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
	const ssh = new tls.PrivateKey(
		`${name}-edge-ssh-key`,
		{
			algorithm: "ED25519",
		},
		opts,
	);

	return {
		caCertB64: encodeBase64(ca.certPem),
		edgeCertB64: encodeBase64(edge.certificate.certPem),
		edgeKeyB64: encodeBase64(edge.key.privateKeyPemPkcs8),
		intermediateCertB64: pulumi
			.all([intermediate.certPem, ca.certPem])
			.apply(([leaf, root]) =>
				Buffer.from(leaf + root, "utf8").toString("base64"),
			),
		intermediateKeyB64: encodeBase64(intermediateKey.privateKeyPemPkcs8),
		connectors,
		sshPublicKey: ssh.publicKeyOpenssh.apply((value) => value.trim()),
		sshPrivateKey: ssh.privateKeyOpenssh,
	};
}

function createLeaf(
	name: string,
	role: "edge" | "connector",
	usage: "server_auth" | "client_auth",
	identity: string,
	ca: tls.SelfSignedCert,
	caKey: tls.PrivateKey,
	opts?: pulumi.ComponentResourceOptions,
): { key: tls.PrivateKey; certificate: tls.LocallySignedCert } {
	const key = new tls.PrivateKey(`${name}-key`, { algorithm: "ED25519" }, opts);
	const request = new tls.CertRequest(
		`${name}-request`,
		{
			privateKeyPem: key.privateKeyPem,
			uris: [`spiffe://tailbridge.local/${role}/${identity}`],
			subject: { commonName: `tailbridge-${role}-${identity}` },
		},
		opts,
	);
	const certificate = new tls.LocallySignedCert(
		`${name}-certificate`,
		{
			certRequestPem: request.certRequestPem,
			caPrivateKeyPem: caKey.privateKeyPem,
			caCertPem: ca.certPem,
			validityPeriodHours: 24 * 90,
			earlyRenewalHours: 24 * 30,
			allowedUses: ["digital_signature", usage],
		},
		opts,
	);
	return { key, certificate };
}

function encodeBase64(value: pulumi.Output<string>): pulumi.Output<string> {
	return value.apply((pem) => Buffer.from(pem, "utf8").toString("base64"));
}
