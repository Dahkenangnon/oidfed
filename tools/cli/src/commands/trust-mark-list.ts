import { FederationEndpoint, type HttpClient, ok, type Result } from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { normalizeEntityId, parseEntityIdOrError } from "../util/entity-id.js";
import { fetchTextOrError } from "../util/http.js";
import type { Logger } from "../util/logger.js";
import { parseJsonOrError } from "../util/parse.js";

export interface TrustMarkListDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface TrustMarkListArgs {
	readonly entityId: string;
	readonly trustMarkType?: string | undefined;
}

export async function handler(
	args: TrustMarkListArgs,
	deps: TrustMarkListDeps,
): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;
	const base = normalizeEntityId(args.entityId);

	let url = `${base}${FederationEndpoint.TrustMarkList}`;
	if (args.trustMarkType) {
		url += `?trust_mark_type=${encodeURIComponent(args.trustMarkType)}`;
	}

	deps.logger.info(`Fetching ${url}`);

	const bodyResult = await fetchTextOrError(deps.httpClient, url, "Trust mark list failed");
	if (!bodyResult.ok) return bodyResult;

	const parsed = parseJsonOrError(bodyResult.value);
	if (!parsed.ok) return parsed;

	return ok(deps.formatter.format(parsed.value));
}

export function register(program: Command, deps: TrustMarkListDeps): void {
	program
		.command("trust-mark-list")
		.description("List trust marks from an entity")
		.argument("<entity-id>", "Entity hosting the trust mark list endpoint")
		.option("--trust-mark-type <type>", "Filter by trust mark type")
		.action(async (entityIdArg: string, opts: { trustMarkType?: string }) => {
			const result = await handler(
				{ entityId: entityIdArg, trustMarkType: opts.trustMarkType },
				deps,
			);
			if (result.ok) {
				process.stdout.write(`${result.value}\n`);
			} else {
				deps.logger.error(result.error.description);
				process.exitCode = 1;
			}
		});
}
