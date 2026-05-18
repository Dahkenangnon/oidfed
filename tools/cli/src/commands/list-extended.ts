import {
	type EntityType,
	type ExtendedListClaim,
	type ExtendedListRequestParams,
	type ExtendedListResponse,
	fetchExtendedSubordinatesList,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { discoverEndpoint } from "../util/discover-endpoint.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface ListExtendedDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface ListExtendedArgs {
	readonly entityId: string;
	readonly from?: string | undefined;
	readonly limit?: number | undefined;
	readonly updatedAfter?: number | undefined;
	readonly updatedBefore?: number | undefined;
	readonly auditTimestamps?: boolean | undefined;
	readonly claims?: ReadonlyArray<string> | undefined;
	readonly entityType?: string | undefined;
	readonly trustMarked?: boolean | undefined;
	readonly trustMarkType?: string | undefined;
	readonly intermediate?: boolean | undefined;
	readonly extendedListEndpoint?: string | undefined;
}

export async function handler(
	args: ListExtendedArgs,
	deps: ListExtendedDeps,
): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;

	let endpoint: string;
	if (args.extendedListEndpoint) {
		endpoint = args.extendedListEndpoint;
	} else {
		const epResult = await discoverEndpoint(
			eidResult.value,
			"federation_extended_list_endpoint",
			deps.httpClient,
		);
		if (!epResult.ok) return epResult;
		endpoint = epResult.value;
	}

	const params: ExtendedListRequestParams = {};
	if (args.from !== undefined) params.fromEntityId = args.from;
	if (args.limit !== undefined) params.limit = args.limit;
	if (args.updatedAfter !== undefined) params.updatedAfter = args.updatedAfter;
	if (args.updatedBefore !== undefined) params.updatedBefore = args.updatedBefore;
	if (args.auditTimestamps !== undefined) params.auditTimestamps = args.auditTimestamps;
	if (args.claims !== undefined) {
		params.claims = args.claims as ReadonlyArray<ExtendedListClaim | string>;
	}
	if (args.entityType !== undefined) params.entityType = args.entityType as EntityType;
	if (args.trustMarked !== undefined) params.trustMarked = args.trustMarked;
	if (args.trustMarkType !== undefined) params.trustMarkType = args.trustMarkType;
	if (args.intermediate !== undefined) params.intermediate = args.intermediate;

	deps.logger.info(`Fetching extended subordinate listing from ${endpoint}`);
	const result = await fetchExtendedSubordinatesList(endpoint, params, {
		httpClient: deps.httpClient,
	});
	if (!result.ok) return result;

	return ok(deps.formatter.format(result.value as ExtendedListResponse));
}

function parsePositiveIntOption(raw: string): number {
	if (!/^[1-9][0-9]*$/.test(raw)) {
		throw new Error(`expected positive integer, got '${raw}'`);
	}
	return Number.parseInt(raw, 10);
}

function parseNumericDateOption(raw: string): number {
	if (!/^[0-9]+$/.test(raw)) {
		throw new Error(`expected NumericDate (non-negative integer), got '${raw}'`);
	}
	return Number.parseInt(raw, 10);
}

export function register(program: Command, deps: ListExtendedDeps): void {
	program
		.command("list-extended")
		.description(
			"List subordinate entities of an authority via the Extended Subordinate Listing endpoint (paginated, with bulk claim retrieval)",
		)
		.argument("<entity-id>", "Authority entity ID")
		.option("--from <entity-id>", "Resume cursor: from_entity_id (inclusive)")
		.option("--limit <n>", "Maximum number of entities to return", parsePositiveIntOption)
		.option(
			"--updated-after <numericdate>",
			"Filter to entities updated at/after this NumericDate",
			parseNumericDateOption,
		)
		.option(
			"--updated-before <numericdate>",
			"Filter to entities updated at/before this NumericDate",
			parseNumericDateOption,
		)
		.option("--audit-timestamps", "Include 'registered' and 'updated' fields per entity")
		.option(
			"--claims <name>",
			"Repeatable: request a top-level Entity Statement claim per entity (e.g. subordinate_statement, trust_marks, metadata)",
			(value: string, previous: string[] | undefined) => [...(previous ?? []), value],
		)
		.option("--entity-type <type>", "Inherited base filter: only this entity type")
		.option("--trust-marked", "Inherited base filter: only entities with a recognised Trust Mark")
		.option("--trust-mark-type <id>", "Inherited base filter: trust mark type identifier")
		.option("--intermediate", "Inherited base filter: only intermediate authorities")
		.option(
			"--extended-list-endpoint <url>",
			"Override federation_extended_list_endpoint discovery (advanced)",
		)
		.action(
			async (
				entityIdArg: string,
				opts: {
					from?: string;
					limit?: number;
					updatedAfter?: number;
					updatedBefore?: number;
					auditTimestamps?: boolean;
					claims?: string[];
					entityType?: string;
					trustMarked?: boolean;
					trustMarkType?: string;
					intermediate?: boolean;
					extendedListEndpoint?: string;
				},
			) => {
				const result = await handler(
					{
						entityId: entityIdArg,
						from: opts.from,
						limit: opts.limit,
						updatedAfter: opts.updatedAfter,
						updatedBefore: opts.updatedBefore,
						auditTimestamps: opts.auditTimestamps,
						claims: opts.claims,
						entityType: opts.entityType,
						trustMarked: opts.trustMarked,
						trustMarkType: opts.trustMarkType,
						intermediate: opts.intermediate,
						extendedListEndpoint: opts.extendedListEndpoint,
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
