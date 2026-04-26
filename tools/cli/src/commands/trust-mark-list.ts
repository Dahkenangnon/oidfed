import {
	type EntityId,
	err,
	FederationErrorCode,
	federationError,
	fetchTrustMarkList,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { discoverEndpoint } from "../util/discover-endpoint.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface TrustMarkListDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface TrustMarkListArgs {
	readonly entityId: string;
	readonly trustMarkType?: string | undefined;
	readonly sub?: string | undefined;
	readonly listEndpoint?: string | undefined;
}

export async function handler(
	args: TrustMarkListArgs,
	deps: TrustMarkListDeps,
): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;

	if (!args.trustMarkType) {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "--trust-mark-type is required"),
		);
	}

	let endpoint: string;
	if (args.listEndpoint) {
		endpoint = args.listEndpoint;
	} else {
		const epResult = await discoverEndpoint(
			eidResult.value,
			"federation_trust_mark_list_endpoint",
			deps.httpClient,
		);
		if (!epResult.ok) return epResult;
		endpoint = epResult.value;
	}

	let subEid: EntityId | undefined;
	if (args.sub) {
		const subResult = parseEntityIdOrError(args.sub);
		if (!subResult.ok) return subResult;
		subEid = subResult.value;
	}

	deps.logger.info(`Fetching trust mark list from ${endpoint}`);
	const params: { trustMarkType: string; sub?: EntityId } = {
		trustMarkType: args.trustMarkType,
	};
	if (subEid) params.sub = subEid;

	const result = await fetchTrustMarkList(endpoint, params, { httpClient: deps.httpClient });
	if (!result.ok) return result;

	return ok(deps.formatter.format(result.value));
}

export function register(program: Command, deps: TrustMarkListDeps): void {
	program
		.command("trust-mark-list")
		.description("List entities holding an active Trust Mark of a given type")
		.argument("<entity-id>", "Trust Mark Issuer entity ID")
		.requiredOption("--trust-mark-type <id>", "Trust Mark type identifier")
		.option("--sub <url>", "Filter to a specific subject Entity Identifier")
		.option(
			"--list-endpoint <url>",
			"Override federation_trust_mark_list_endpoint discovery (advanced)",
		)
		.action(
			async (
				entityIdArg: string,
				opts: { trustMarkType: string; sub?: string; listEndpoint?: string },
			) => {
				const result = await handler(
					{
						entityId: entityIdArg,
						trustMarkType: opts.trustMarkType,
						sub: opts.sub,
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
