import {
	type EntityType,
	fetchListSubordinates,
	type HttpClient,
	type ListSubordinatesFilter,
	ok,
	type Result,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { discoverEndpoint } from "../util/discover-endpoint.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface ListDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface ListArgs {
	readonly entityId: string;
	readonly entityType?: string | undefined;
	readonly trustMarked?: boolean | undefined;
	readonly trustMarkType?: string | undefined;
	readonly intermediate?: boolean | undefined;
	readonly listEndpoint?: string | undefined;
}

export async function handler(args: ListArgs, deps: ListDeps): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;

	let endpoint: string;
	if (args.listEndpoint) {
		endpoint = args.listEndpoint;
	} else {
		const epResult = await discoverEndpoint(
			eidResult.value,
			"federation_list_endpoint",
			deps.httpClient,
		);
		if (!epResult.ok) return epResult;
		endpoint = epResult.value;
	}

	const filter: ListSubordinatesFilter = {};
	if (args.entityType) filter.entityType = args.entityType as EntityType;
	if (args.trustMarked !== undefined) filter.trustMarked = args.trustMarked;
	if (args.trustMarkType) filter.trustMarkType = args.trustMarkType;
	if (args.intermediate !== undefined) filter.intermediate = args.intermediate;

	deps.logger.info(`Fetching subordinate list from ${endpoint}`);
	const result = await fetchListSubordinates(endpoint, filter, { httpClient: deps.httpClient });
	if (!result.ok) return result;

	return ok(deps.formatter.format(result.value));
}

export function register(program: Command, deps: ListDeps): void {
	program
		.command("list")
		.description("List subordinate entities of an authority")
		.argument("<entity-id>", "Authority entity ID")
		.option("--entity-type <type>", "Filter by entity type")
		.option("--trust-marked", "Only list entities that have a recognised Trust Mark")
		.option("--trust-mark-type <id>", "Filter by trust mark type identifier")
		.option("--intermediate", "Only list intermediate authorities")
		.option("--list-endpoint <url>", "Override the federation_list_endpoint discovery (advanced)")
		.action(
			async (
				entityIdArg: string,
				opts: {
					entityType?: string;
					trustMarked?: boolean;
					trustMarkType?: string;
					intermediate?: boolean;
					listEndpoint?: string;
				},
			) => {
				const result = await handler(
					{
						entityId: entityIdArg,
						entityType: opts.entityType,
						trustMarked: opts.trustMarked,
						trustMarkType: opts.trustMarkType,
						intermediate: opts.intermediate,
						listEndpoint: opts.listEndpoint,
					},
					deps,
				);
				if (result.ok) {
					process.stdout.write(`${result.value}\n`);
				} else {
					deps.logger.error(result.error.description);
					process.exitCode = 1;
				}
			},
		);
}
