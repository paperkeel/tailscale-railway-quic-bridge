import { writeFile } from "node:fs/promises";

const variables = {
	sourceCommit: "TAILBRIDGE_SOURCE_COMMIT",
	packageVersion: "TAILBRIDGE_PACKAGE_VERSION",
	edgeImage: "TAILBRIDGE_EDGE_IMAGE",
	connectorImage: "TAILBRIDGE_CONNECTOR_IMAGE",
};

const build = Object.fromEntries(
	Object.entries(variables).map(([field, name]) => {
		const value = process.env[name]?.trim();
		if (!value) throw new Error(`${name} must be set.`);
		return [field, value];
	}),
);

for (const field of ["edgeImage", "connectorImage"]) {
	if (!/@sha256:[0-9a-f]{64}$/.test(build[field])) {
		throw new Error(`${variables[field]} must be an image digest reference.`);
	}
}

const contents = `import type { TailbridgeBuild } from "./build";

export const generatedBuild: TailbridgeBuild = ${JSON.stringify(build, null, "\t")};
`;

await writeFile(new URL("./build.generated.ts", import.meta.url), contents);
