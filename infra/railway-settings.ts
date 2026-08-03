import * as pulumi from "@pulumi/pulumi";

const railwayGraphqlEndpoint =
	"https://backboard.railway.app/graphql/v2?source=tailbridge_sst";
const railwayRequestTimeoutMilliseconds = 30_000;

export interface RailwayServiceSettingsArgs {
	environmentId: pulumi.Input<string>;
	region: pulumi.Input<string>;
	serviceId: pulumi.Input<string>;
}

interface RailwayServiceSettingsInputs {
	environmentId: string;
	region: string;
	serviceId: string;
}

interface GraphqlResponse<T> {
	data?: T;
	errors?: { message: string }[];
}

export async function requestRailwayGraphql<T>(
	query: string,
	variables: Record<string, unknown>,
	token: string,
	request: typeof fetch = fetch,
): Promise<T> {
	const response = await request(railwayGraphqlEndpoint, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${token}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({ query, variables }),
		signal: AbortSignal.timeout(railwayRequestTimeoutMilliseconds),
	});
	const body = await response.text();
	let parsed: unknown;
	try {
		parsed = JSON.parse(body);
	} catch {
		throw new Error(
			`Railway GraphQL request failed (${response.status}): The response was not valid JSON.`,
		);
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new Error(
			`Railway GraphQL request failed (${response.status}): The response did not contain a GraphQL result.`,
		);
	}
	const result = parsed as GraphqlResponse<T>;
	if (!response.ok || result.errors?.length || !result.data) {
		const details = result.errors?.map((error) => error.message).join(", ");
		throw new Error(
			`Railway GraphQL request failed (${response.status})${details ? `: ${details}` : "."}`,
		);
	}
	if (
		typeof result.data === "object" &&
		result.data !== null &&
		Object.values(result.data).some((value) => value === false)
	) {
		throw new Error(
			`Railway GraphQL request failed (${response.status}): The mutation returned false.`,
		);
	}
	return result.data;
}

class RailwayServiceSettingsProvider
	implements pulumi.dynamic.ResourceProvider
{
	async create(
		inputs: RailwayServiceSettingsInputs,
	): Promise<pulumi.dynamic.CreateResult> {
		await this.apply(inputs);
		return {
			id: `${inputs.environmentId}:${inputs.serviceId}`,
			outs: inputs,
		};
	}

	async diff(
		_id: pulumi.ID,
		olds: RailwayServiceSettingsInputs,
		news: RailwayServiceSettingsInputs,
	): Promise<pulumi.dynamic.DiffResult> {
		return {
			changes:
				olds.environmentId !== news.environmentId ||
				olds.region !== news.region ||
				olds.serviceId !== news.serviceId,
			replaces:
				olds.environmentId !== news.environmentId ||
				olds.serviceId !== news.serviceId
					? ["environmentId", "serviceId"]
					: [],
		};
	}

	async update(
		_id: pulumi.ID,
		_olds: RailwayServiceSettingsInputs,
		news: RailwayServiceSettingsInputs,
	): Promise<pulumi.dynamic.UpdateResult> {
		await this.apply(news);
		return { outs: news };
	}

	async delete(): Promise<void> {}

	private async apply(inputs: RailwayServiceSettingsInputs): Promise<void> {
		await this.graphql<{ serviceInstanceUpdate: boolean }>(
			`mutation TailbridgeServiceInstanceUpdate(
				$environmentId: String!
				$serviceId: String!
				$input: ServiceInstanceUpdateInput!
			) {
				serviceInstanceUpdate(
					environmentId: $environmentId
					serviceId: $serviceId
					input: $input
				)
			}`,
			{
				environmentId: inputs.environmentId,
				serviceId: inputs.serviceId,
				input: {
					drainingSeconds: 15,
					healthcheckPath: "/readyz",
					healthcheckTimeout: 60,
					multiRegionConfig: {
						[inputs.region]: { numReplicas: 1 },
					},
					overlapSeconds: 20,
					restartPolicyType: "ALWAYS",
				},
			},
		);

		await this.graphql<{ environmentPatchCommit: boolean }>(
			`mutation TailbridgeEnvironmentPatchCommit(
				$environmentId: String!
				$patch: EnvironmentConfig!
			) {
				environmentPatchCommit(
					environmentId: $environmentId
					patch: $patch
					commitMessage: "Configure Tailbridge connector networking"
				)
			}`,
			{
				environmentId: inputs.environmentId,
				patch: {
					services: {
						[inputs.serviceId]: {
							deploy: { ipv6EgressEnabled: false },
						},
					},
				},
			},
		);
	}

	private async graphql<T>(
		query: string,
		variables: Record<string, unknown>,
	): Promise<T> {
		const token = process.env.RAILWAY_TOKEN?.trim();
		if (!token) {
			throw new Error("RAILWAY_TOKEN must be set.");
		}

		return requestRailwayGraphql<T>(query, variables, token);
	}
}

export class RailwayServiceSettings extends pulumi.dynamic.Resource {
	constructor(
		name: string,
		args: RailwayServiceSettingsArgs,
		opts?: pulumi.CustomResourceOptions,
	) {
		super(new RailwayServiceSettingsProvider(), name, args, opts);
	}
}
