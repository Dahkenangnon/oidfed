import {
	calculateChainExpiration,
	decodeEntityStatement,
	err,
	FederationErrorCode,
	federationError,
	type HttpClient,
	nowSeconds,
	ok,
	type ParsedEntityStatement,
	type Result,
	validateTrustChain,
} from "@oidfed/core";
import type { Command } from "commander";
import type { Config } from "../config.js";
import type { OutputFormatter } from "../output/index.js";
import { isEntityId, parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";
import { requireAnchorIds, resolveOrError } from "../util/trust-anchors.js";

export interface ExpiryDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly config: Config;
}

export interface ExpiryArgs {
	readonly jwt: string;
	readonly trustAnchors?: readonly string[] | undefined;
}

async function handleEntityIdMode(
	entityUrl: string,
	trustAnchorArgs: readonly string[],
	deps: ExpiryDeps,
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
	);
	if (!resolveResult.ok) return resolveResult;
	const { anchors, result: resolved } = resolveResult.value;

	const chain = resolved.chains[0];
	if (!chain) {
		return err(federationError(FederationErrorCode.InvalidTrustChain, "No trust chains resolved"));
	}
	const validationResult = await validateTrustChain([...chain.statements], anchors);

	if (!validationResult.valid) {
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`Chain validation failed: ${validationResult.errors.map((e) => e.message).join("; ")}`,
			),
		);
	}

	// Decode all statements to calculate chain expiration
	const parsedStatements: ParsedEntityStatement[] = [];
	for (const stmt of chain.statements) {
		const decoded = decodeEntityStatement(stmt);
		if (decoded.ok) parsedStatements.push(decoded.value);
	}

	const chainExp = calculateChainExpiration(parsedStatements);
	const now = nowSeconds();
	const remainingSeconds = chainExp - now;
	const expired = remainingSeconds <= 0;
	const warningThresholdHours = 24;
	const warningThresholdSeconds = warningThresholdHours * 3600;

	return ok(
		deps.formatter.format({
			entity_id: entityUrl,
			trust_anchor_id: validationResult.chain.trustAnchorId,
			chain_expires_at: new Date(chainExp * 1000).toISOString(),
			expired,
			remaining_seconds: Math.max(0, remainingSeconds),
			warning: !expired && remainingSeconds < warningThresholdSeconds,
			statements: parsedStatements.length,
		}),
	);
}

export function handleJwt(jwt: string, deps: ExpiryDeps): Result<string> {
	const decoded = decodeEntityStatement(jwt);
	if (!decoded.ok) return decoded;

	const payload = decoded.value.payload as Record<string, unknown>;
	const iat = payload.iat as number | undefined;
	const exp = payload.exp as number | undefined;
	const iss = payload.iss as string | undefined;
	const sub = payload.sub as string | undefined;

	if (!exp) {
		return err(federationError(FederationErrorCode.InvalidRequest, "JWT has no exp claim"));
	}

	const now = nowSeconds();
	const remainingSeconds = exp - now;
	const expired = remainingSeconds <= 0;

	return ok(
		deps.formatter.format({
			issuer: iss ?? "unknown",
			subject: sub ?? "unknown",
			issued_at: iat ? new Date(iat * 1000).toISOString() : "unknown",
			expires_at: new Date(exp * 1000).toISOString(),
			expired,
			remaining_seconds: Math.max(0, remainingSeconds),
		}),
	);
}

export async function handler(args: ExpiryArgs, deps: ExpiryDeps): Promise<Result<string>> {
	if (isEntityId(args.jwt)) {
		return handleEntityIdMode(args.jwt, args.trustAnchors ?? [], deps);
	}
	return handleJwt(args.jwt, deps);
}

export function register(program: Command, deps: ExpiryDeps): void {
	program
		.command("expiry")
		.description("Show expiration details for a JWT or entity trust chain")
		.argument("<jwt-or-entity-id>", "JWT string or entity ID URL")
		.option(
			"-t, --trust-anchor <url>",
			"Trust anchor entity IDs (repeatable, for entity-id mode)",
			(v: string, a: string[]) => [...a, v],
			[] as string[],
		)
		.action(async (jwt: string, opts: { trustAnchor: string[] }) => {
			const result = await handler({ jwt, trustAnchors: opts.trustAnchor }, deps);
			if (result.ok) {
				process.stdout.write(`${result.value}\n`);
			} else {
				deps.logger.error(result.error.description);
				process.exitCode = 1;
			}
		});
}
