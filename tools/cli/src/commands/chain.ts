import {
	chainRemainingTtl,
	checkConstraints,
	decodeEntityStatement,
	describeTrustChain,
	type HttpClient,
	isChainExpired,
	longestExpiry,
	ok,
	type ParsedEntityStatement,
	type Result,
	resolveMetadataPolicy,
	shortestChain,
	validateTrustChain,
} from "@oidfed/core";
import type { Command } from "commander";
import type { Config } from "../config.js";
import type { OutputFormatter } from "../output/index.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";
import { requireAnchorIds, resolveOrError } from "../util/trust-anchors.js";

export interface ChainDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly config: Config;
}

export interface ChainArgs {
	readonly entityId: string;
	readonly trustAnchors: readonly string[];
	readonly maxDepth?: number | undefined;
	readonly strategy?: "shortest" | "longest-expiry" | undefined;
}

export async function handler(args: ChainArgs, deps: ChainDeps): Promise<Result<string>> {
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
	);
	if (!resolveResult.ok) return resolveResult;
	const { anchors, result: resolved } = resolveResult.value;

	const validatedChains = [];
	const results = [];
	for (const chain of resolved.chains) {
		const validationResult = await validateTrustChain([...chain.statements], anchors);
		if (validationResult.valid) {
			validatedChains.push(validationResult.chain);

			// Decode statements for policy/constraints
			const decoded = chain.statements.map((s) => decodeEntityStatement(s));
			const parsedStatements: ParsedEntityStatement[] = [];
			for (const d of decoded) {
				if (d.ok) parsedStatements.push(d.value);
			}

			// Resolve metadata policy
			let policy: unknown;
			if (parsedStatements.length > 0) {
				const policyResult = resolveMetadataPolicy(parsedStatements);
				if (policyResult.ok) {
					policy = policyResult.value;
				}
			}

			// Check constraints
			const constraintResults: { position: number; status: string; error?: string | undefined }[] =
				[];
			for (let i = 0; i < parsedStatements.length; i++) {
				const stmt = parsedStatements[i];
				if (!stmt) continue;
				const payload = stmt.payload as Record<string, unknown>;
				const constraints = payload.constraints as
					| Parameters<typeof checkConstraints>[0]
					| undefined;
				if (constraints) {
					const check = checkConstraints(constraints, i, parsedStatements);
					constraintResults.push({
						position: i,
						status: check.ok ? "pass" : "fail",
						...(check.ok ? {} : { error: check.error.description }),
					});
				}
			}

			results.push({
				description: describeTrustChain(validationResult.chain),
				expired: isChainExpired(validationResult.chain),
				remaining_ttl_seconds: chainRemainingTtl(validationResult.chain),
				entity_id: validationResult.chain.entityId,
				trust_anchor_id: validationResult.chain.trustAnchorId,
				statements: validationResult.chain.statements.length,
				warnings: validationResult.errors.length,
				trust_chain: [...chain.statements],
				...(policy ? { metadata_policy: policy } : {}),
				...(constraintResults.length > 0 ? { constraints: constraintResults } : {}),
			});
		} else {
			results.push({
				description: "invalid",
				errors: validationResult.errors.map((e) => e.message),
			});
		}
	}

	// Apply selection strategy if specified and multiple valid chains
	if (args.strategy && validatedChains.length > 1) {
		const selector = args.strategy === "shortest" ? shortestChain : longestExpiry;
		const selected = selector(validatedChains);
		const selectedIdx = validatedChains.indexOf(selected);
		if (selectedIdx >= 0) {
			return ok(
				deps.formatter.format({ selected: results[selectedIdx], all_chains: results.length }),
			);
		}
	}

	return ok(deps.formatter.format(results));
}

export function register(program: Command, deps: ChainDeps): void {
	program
		.command("chain")
		.description("Resolve and validate trust chains for an entity")
		.argument("<entity-id>", "Entity identifier (URL)")
		.option(
			"-t, --trust-anchor <url>",
			"Trust anchor entity IDs (repeatable)",
			(v: string, a: string[]) => [...a, v],
			[] as string[],
		)
		.option("--max-depth <n>", "Maximum chain depth", Number.parseInt)
		.option("--strategy <type>", "Chain selection: shortest or longest-expiry")
		.action(
			async (
				entityIdArg: string,
				opts: { trustAnchor: string[]; maxDepth?: number; strategy?: string },
			) => {
				const result = await handler(
					{
						entityId: entityIdArg,
						trustAnchors: opts.trustAnchor,
						maxDepth: opts.maxDepth,
						strategy: opts.strategy as "shortest" | "longest-expiry" | undefined,
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
