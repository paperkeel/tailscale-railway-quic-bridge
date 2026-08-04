import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const edgeImageRepository =
	"ghcr.io/bearfire-dev/tailscale-railway-quic-bridge-edge";
const composePath = fileURLToPath(new URL("./compose.yml", import.meta.url));

export interface EdgeEnvironment {
	edgeId: string;
	environment: string;
	connectors: Array<{
		connectorId: string;
		projectId: string;
		environment: string;
		slot: number;
		virtualPrefix: string;
		realPrefix: string;
		dnsSuffix: string;
	}>;
	caCertB64: string;
	edgeCertB64: string;
	edgeKeyB64: string;
	tailscaleAuthKey: string;
	registration?: {
		frozen: boolean;
		newProjectsFrozen?: boolean;
		allowedProjectIds?: string[];
		virtualNetwork: string;
		excludedPrefixes?: string[];
		oidcPolicies: unknown[];
		approvalTailscaleTags?: string[];
		edgeTailscaleTag?: string;
		leases?: { preview?: string; persistent?: string; quarantine?: string };
		intermediateCertB64: string;
		intermediateKeyB64: string;
	};
}

export function renderCloudInit(): string {
	return `#cloud-config
package_update: true
packages:
  - curl
  - docker.io
  - docker-compose-v2
write_files:
  - path: /etc/sysctl.d/99-tailbridge.conf
    permissions: "0644"
    content: |
      net.ipv4.ip_forward=1
      net.ipv6.conf.all.forwarding=1
runcmd:
  - systemctl enable --now docker
  - sysctl --system
  - install -d -m 0700 /opt/tailbridge
`;
}

export function renderEdgeEnvironment(environment: EdgeEnvironment): string {
	const routes = environment.connectors
		.map((connector) => connector.virtualPrefix)
		.join(",");
	const connectors = Buffer.from(
		JSON.stringify(environment.connectors),
		"utf8",
	).toString("base64");
	const values: Record<string, string> = {
		TB_EDGE_ID: environment.edgeId,
		TB_ENVIRONMENT: environment.environment,
		TB_QUIC_LISTEN_ADDR: ":4433",
		TB_TCP_LISTEN_ADDR: "[::]:15001",
		TB_UDP_LISTEN_ADDR: "[::]:15002",
		TB_ADMIN_LISTEN_ADDR: "127.0.0.1:9090",
		TB_MTLS_CA_B64: environment.caCertB64,
		TB_MTLS_CERT_B64: environment.edgeCertB64,
		TB_MTLS_KEY_B64: environment.edgeKeyB64,
		TS_AUTHKEY: environment.tailscaleAuthKey,
		TS_HOSTNAME: environment.edgeId,
		TS_STATE_DIR: "/var/lib/tailscale",
		TS_AUTH_ONCE: "true",
		TS_USERSPACE: "false",
		TS_EXTRA_ARGS: environment.registration
			? `--advertise-tags=${environment.registration.edgeTailscaleTag ?? "tag:tailbridge"}`
			: `--advertise-routes=${routes} --advertise-tags=tag:tailbridge`,
	};
	if (environment.connectors.length) {
		values.TB_CONNECTORS_B64 = connectors;
	}
	if (environment.registration) {
		Object.assign(values, {
			TB_REGISTRATION_MODE: environment.connectors.length
				? "migration"
				: "dynamic",
			TB_REGISTRATION_FROZEN: String(environment.registration.frozen),
			TB_NEW_PROJECTS_FROZEN: String(
				environment.registration.newProjectsFrozen ?? true,
			),
			TB_ALLOWED_PROJECT_IDS_B64: Buffer.from(
				JSON.stringify(environment.registration.allowedProjectIds ?? []),
				"utf8",
			).toString("base64"),
			TB_VIRTUAL_NETWORK: environment.registration.virtualNetwork,
			TB_EXCLUDED_PREFIXES: (
				environment.registration.excludedPrefixes ?? ["fd12::/16"]
			).join(","),
			TB_OIDC_POLICIES_B64: Buffer.from(
				JSON.stringify(environment.registration.oidcPolicies),
				"utf8",
			).toString("base64"),
			TB_APPROVAL_TAILSCALE_TAGS: (
				environment.registration.approvalTailscaleTags ?? ["tag:tailbridge-ci"]
			).join(","),
			TB_PREVIEW_LEASE: environment.registration.leases?.preview ?? "24h",
			TB_PERSISTENT_LEASE:
				environment.registration.leases?.persistent ?? "720h",
			TB_SLOT_QUARANTINE: environment.registration.leases?.quarantine ?? "24h",
			TB_REGISTRATION_LISTEN_ADDR: ":4434",
			TB_APPROVAL_LISTEN_ADDR: "tailscale0:9443",
			TB_DNS_LISTEN_ADDR: "tailscale0:53",
			TB_REGISTRY_PATH: "/var/lib/tailbridge/registry/tailbridge.db",
			TB_INTERMEDIATE_CERT_B64: environment.registration.intermediateCertB64,
			TB_INTERMEDIATE_KEY_B64: environment.registration.intermediateKeyB64,
		});
	}

	return `${Object.entries(values)
		.map(([name, value]) => `${name}=${environmentValue(value)}`)
		.join("\n")}\n`;
}

export function loadComposeTemplate(): string {
	return readFileSync(composePath, "utf8");
}

export function renderCompose(
	image: string,
	template = loadComposeTemplate(),
): string {
	const reference = edgeImageReference(image);
	if (!template.includes("{{EDGE_IMAGE}}")) {
		throw new Error("The edge Compose template must contain {{EDGE_IMAGE}}.");
	}
	return template.replaceAll("{{EDGE_IMAGE}}", reference);
}

export function deploymentHash(...contents: string[]): string {
	const hash = createHash("sha256");
	for (const content of contents) {
		hash.update(String(Buffer.byteLength(content)));
		hash.update(":");
		hash.update(content);
	}
	return hash.digest("hex");
}

export function edgeImageReference(image: string): string {
	if (image !== image.trim() || !image || /\s/.test(image)) {
		throw new Error("The edge image reference must not contain whitespace.");
	}
	const repositoryAndTag = image.split("@", 1)[0];
	if (repositoryAndTag === "latest" || repositoryAndTag.endsWith(":latest")) {
		throw new Error("The edge image reference must not use the latest tag.");
	}
	if (image.startsWith("sha256:")) {
		validateDigest(image);
		return `${edgeImageRepository}@${image}`;
	}
	if (image.includes("@")) {
		const [repository, digest, extra] = image.split("@");
		if (
			extra !== undefined ||
			(!isRepository(repository) && !isTaggedRepository(repository))
		) {
			throw new Error("The edge image reference is invalid.");
		}
		validateDigest(digest);
		return image;
	}
	if (image.includes("/")) {
		if (!isTaggedRepository(image)) {
			throw new Error("The edge image reference must include a tag or digest.");
		}
		return image;
	}
	if (image.includes(":")) {
		if (!isTaggedRepository(image)) {
			throw new Error("The edge image reference is invalid.");
		}
		return image;
	}
	if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(image)) {
		throw new Error("The edge image tag is invalid.");
	}
	return `${edgeImageRepository}:${image}`;
}

function validateDigest(digest: string): void {
	if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
		throw new Error("The edge image digest must be a complete SHA-256 digest.");
	}
}

function isRepository(repository: string): boolean {
	return /^(?:[a-zA-Z0-9.-]+(?::[0-9]+)?\/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(
		repository,
	);
}

function isTaggedRepository(reference: string): boolean {
	const separator = reference.lastIndexOf(":");
	const slash = reference.lastIndexOf("/");
	if (separator <= slash) return false;
	return (
		isRepository(reference.slice(0, separator)) &&
		/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(reference.slice(separator + 1))
	);
}

function environmentValue(value: string): string {
	if (value.includes("\n") || value.includes("\r")) {
		throw new Error("Edge environment values must not contain newlines.");
	}
	return value;
}
