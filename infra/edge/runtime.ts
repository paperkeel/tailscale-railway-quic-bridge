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
		TB_ALLOWED_ROUTES: routes,
		TB_CONNECTORS_B64: connectors,
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
		TS_EXTRA_ARGS: `--advertise-routes=${routes} --advertise-tags=tag:tailbridge`,
	};

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
	const reference = imageReference(image);
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

function imageReference(image: string): string {
	if (image.includes("/")) {
		return image;
	}
	if (image.startsWith("sha256:")) {
		return `${edgeImageRepository}@${image}`;
	}
	return `${edgeImageRepository}:${image}`;
}

function environmentValue(value: string): string {
	if (value.includes("\n") || value.includes("\r")) {
		throw new Error("Edge environment values must not contain newlines.");
	}
	return value;
}
