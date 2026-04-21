import { FederationEndpoint, type HttpClient, ok, type Result } from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { normalizeEntityId, parseEntityIdOrError } from "../util/entity-id.js";
import { fetchTextOrError } from "../util/http.js";
import type { Logger } from "../util/logger.js";
import { parseJsonOrError } from "../util/parse.js";

export interface ListDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface ListArgs {
	readonly entityId: string;
	readonly entityType?: string | undefined;
	readonly trustMarked?: boolean | undefined;
	readonly trustMarkId?: string | undefined;
	readonly intermediate?: boolean | undefined;
}

export async function handler(args: ListArgs, deps: ListDeps): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;
	const base = normalizeEntityId(args.entityId);

	let url = `${base}${FederationEndpoint.List}`;
	const params = new URLSearchParams();
	if (args.entityType) {
		params.set("entity_type", args.entityType);
	}
	if (args.trustMarked) {
		params.set("is_leaf", "false");
	}
	if (args.trustMarkId) {
		params.set("trust_mark_id", args.trustMarkId);
	}
	if (args.intermediate) {
		params.set("intermediate", "true");
	}
	const qs = params.toString();
	if (qs) {
		url += `?${qs}`;
	}

	deps.logger.info(`Fetching ${url}`);

	const bodyResult = await fetchTextOrError(deps.httpClient, url, "List failed");
	if (!bodyResult.ok) return bodyResult;

	const parsed = parseJsonOrError(bodyResult.value);
	if (!parsed.ok) return parsed;

	return ok(deps.formatter.format(parsed.value));
}

export function register(program: Command, deps: ListDeps): void {
	program
		.command("list")
		.description("List subordinate entities of an authority")
		.argument("<entity-id>", "Authority entity ID")
		.option("--entity-type <type>", "Filter by entity type")
		.option("--trust-marked", "Only list trust-marked entities (non-leaf)")
		.option("--trust-mark-id <id>", "Filter by trust mark ID")
		.option("--intermediate", "Include intermediate entities")
		.action(
			async (
				entityIdArg: string,
				opts: {
					entityType?: string;
					trustMarked?: boolean;
					trustMarkId?: string;
					intermediate?: boolean;
				},
			) => {
				const result = await handler(
					{
						entityId: entityIdArg,
						entityType: opts.entityType,
						trustMarked: opts.trustMarked,
						trustMarkId: opts.trustMarkId,
						intermediate: opts.intermediate,
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
