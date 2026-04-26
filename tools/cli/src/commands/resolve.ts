import { type HttpClient, ok, type Result } from "@oidfed/core";
import type { Command } from "commander";
import type { Config } from "../config.js";
import type { OutputFormatter } from "../output/index.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";
import { requireAnchorIds, resolveOrError } from "../util/trust-anchors.js";

export interface ResolveDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly config: Config;
}

export interface ResolveArgs {
	readonly entityId: string;
	readonly trustAnchors: readonly string[];
	readonly maxDepth?: number | undefined;
}

export async function handler(args: ResolveArgs, deps: ResolveDeps): Promise<Result<string>> {
	const anchorResult = requireAnchorIds(args.trustAnchors, deps.config);
	if (!anchorResult.ok) return anchorResult;

	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;
	const eid = eidResult.value;

	const resolveResult = await resolveOrError(
		eid,
		anchorResult.value,
		deps.httpClient,
		args.maxDepth ?? deps.config.max_chain_depth,
		deps.config,
	);
	if (!resolveResult.ok) return resolveResult;
	const result = resolveResult.value.result;

	const summary = result.chains.map((chain) => ({
		entity_id: chain.entityId,
		trust_anchor_id: chain.trustAnchorId,
		statements: chain.statements.length,
		expires_at: new Date(chain.expiresAt * 1000).toISOString(),
	}));

	return ok(
		deps.formatter.format({
			chains_found: result.chains.length,
			errors: result.errors.length,
			chains: summary,
		}),
	);
}

export function register(program: Command, deps: ResolveDeps): void {
	program
		.command("resolve")
		.description("Resolve trust chains for an entity")
		.argument("<entity-id>", "Entity identifier (URL)")
		.option(
			"-t, --trust-anchor <url>",
			"Trust anchor entity IDs (repeatable)",
			(v: string, a: string[]) => [...a, v],
			[] as string[],
		)
		.option("--max-depth <n>", "Maximum chain depth", Number.parseInt)
		.action(async (entityIdArg: string, opts: { trustAnchor: string[]; maxDepth?: number }) => {
			const result = await handler(
				{ entityId: entityIdArg, trustAnchors: opts.trustAnchor, maxDepth: opts.maxDepth },
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
