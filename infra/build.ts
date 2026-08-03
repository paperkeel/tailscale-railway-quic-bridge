export interface TailbridgeBuild {
	sourceCommit: string;
	packageVersion: string;
	edgeImage: string;
	connectorImage: string;
}

import { generatedBuild } from "./build.generated";

export const tailbridgeBuild: Readonly<TailbridgeBuild> =
	Object.freeze(generatedBuild);

export function isDevelopmentBuild(build: TailbridgeBuild): boolean {
	return build.sourceCommit === "development";
}
