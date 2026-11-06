import {
	chainRemainingTtl,
	describeTrustChain,
	err,
	FederationErrorCode,
	federationError,
	type HttpClient,
	isChainExpired,
	isValidEntityId,
	ok,
	type Result,
	validateTrustChain,
} from "@oidfed/core";
import type { Command } from "commander";
import type { Config } from "../config.js";
import type { OutputFormatter } from "../output/index.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";
import { buildTrustAnchors, requireAnchorIds, resolveOrError } from "../util/trust-anchors.js";

export interface ValidateDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly config: Config;
}

export interface ValidateArgs {
	readonly jwts: readonly string[];
	readonly trustAnchors: readonly string[];
}

async function handleEntityIdMode(
	entityUrl: string,
	trustAnchorArgs: readonly string[],
	deps: ValidateDeps,
): Promise<Result<string>> {
	const anchorResult = requireAnchorIds(trustAnchorArgs, deps.config);
	if (!anchorResult.ok) return anchorResult;
	const anchorIds = anchorResult.value;

	const eidResult = parseEntityIdOrError(entityUrl);
	if (!eidResult.ok) return eidResult;
	const eid = eidResult.value;

	deps.logger.info(`Resolving trust chains for ${entityUrl}`);
	const resolveResult = await resolveOrError(
		eid,
		anchorIds,
		deps.httpClient,
		deps.config.max_chain_depth,
		deps.config,
	);
	if (!resolveResult.ok) return resolveResult;
	const { anchors, result: resolved } = resolveResult.value;

	// Validate first resolvable chain
	const chain = resolved.chains[0];
	if (!chain) {
		return err(federationError(FederationErrorCode.InvalidTrustChain, "No trust chains resolved"));
	}
	const validationResult = await validateTrustChain([...chain.statements], anchors);

	const chainValid = validationResult.valid;
	const output: Record<string, unknown> = {
		valid: chainValid,
		entity_id: entityUrl,
	};

	if (chainValid) {
		output.description = describeTrustChain(validationResult.chain);
		output.expired = isChainExpired(validationResult.chain);
		output.remaining_ttl_seconds = chainRemainingTtl(validationResult.chain);
		output.trust_anchor_id = validationResult.chain.trustAnchorId;
		output.statements = validationResult.chain.statements.length;
	} else {
		output.errors = validationResult.errors.map((e) => ({
			code: e.code,
			message: e.message,
		}));
	}

	if (validationResult.valid) {
		output.trust_marks = validationResult.chain.trustMarkEvaluations;
	}

	return ok(deps.formatter.format(output));
}

export async function handler(args: ValidateArgs, deps: ValidateDeps): Promise<Result<string>> {
	// Auto-detect: if first arg starts with http, treat as entity-id mode
	const firstArg = args.jwts[0];
	if (args.jwts.length === 1 && firstArg && isValidEntityId(firstArg)) {
		return handleEntityIdMode(firstArg, args.trustAnchors, deps);
	}

	if (args.jwts.length === 0) {
		return err(federationError(FederationErrorCode.InvalidRequest, "At least one JWT is required"));
	}

	const anchorResult = requireAnchorIds(args.trustAnchors, deps.config);
	if (!anchorResult.ok) return anchorResult;

	const anchorsResult = await buildTrustAnchors(anchorResult.value, deps.httpClient, deps.config);
	if (!anchorsResult.ok) return anchorsResult;

	const validationResult = await validateTrustChain([...args.jwts], anchorsResult.value);

	if (validationResult.valid) {
		return ok(
			deps.formatter.format({
				valid: true,
				description: describeTrustChain(validationResult.chain),
				expired: isChainExpired(validationResult.chain),
				remaining_ttl_seconds: chainRemainingTtl(validationResult.chain),
				entity_id: validationResult.chain.entityId,
				trust_anchor_id: validationResult.chain.trustAnchorId,
				statements: validationResult.chain.statements.length,
				trust_marks: validationResult.chain.trustMarkEvaluations,
			}),
		);
	}

	return ok(
		deps.formatter.format({
			valid: false,
			errors: validationResult.errors.map((e) => ({
				code: e.code,
				message: e.message,
				statement_index: e.statementIndex,
				field: e.field,
			})),
		}),
	);
}

export function register(program: Command, deps: ValidateDeps): void {
	program
		.command("validate")
		.description("Validate a trust chain from JWTs or by resolving an entity ID")
		.argument(
			"<jwt-or-entity-id...>",
			"JWT entity statements (leaf → TA) or a single entity ID URL",
		)
		.option(
			"-t, --trust-anchor <url>",
			"Trust anchor entity IDs (repeatable)",
			(v: string, a: string[]) => [...a, v],
			[] as string[],
		)
		.action(async (jwts: string[], opts: { trustAnchor: string[] }) => {
			const result = await handler({ jwts, trustAnchors: opts.trustAnchor }, deps);
			if (result.ok) {
				process.stdout.write(`${result.value}\n`);
			} else {
				deps.logger.error(result.error.description);
				process.exitCode = 1;
			}
		});
}
