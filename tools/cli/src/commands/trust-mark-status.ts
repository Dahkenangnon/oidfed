import {
	decodeEntityStatement,
	err,
	FederationEndpoint,
	FederationErrorCode,
	federationError,
	fetchEntityConfiguration,
	type HttpClient,
	ok,
	type Result,
	verifyTrustMarkStatusResponse,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { extractJwks, normalizeEntityId, parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface TrustMarkStatusDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface TrustMarkStatusArgs {
	readonly entityId: string;
	readonly trustMark?: string | undefined;
	readonly subject?: string | undefined;
	readonly trustMarkId?: string | undefined;
	readonly verify: boolean;
}

export async function handler(
	args: TrustMarkStatusArgs,
	deps: TrustMarkStatusDeps,
): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;
	const base = normalizeEntityId(args.entityId);

	const hasTrustMark = !!args.trustMark;
	const hasSubjectId = !!args.subject && !!args.trustMarkId;

	if (!hasTrustMark && !hasSubjectId) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Either --trust-mark or both --subject and --trust-mark-id are required",
			),
		);
	}
	if (hasTrustMark && hasSubjectId) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Cannot use --trust-mark together with --subject/--trust-mark-id",
			),
		);
	}

	const url = `${base}${FederationEndpoint.TrustMarkStatus}`;
	deps.logger.info(`POSTing to ${url}`);

	const formParams = hasTrustMark
		? { trust_mark: args.trustMark as string }
		: { sub: args.subject as string, id: args.trustMarkId as string };
	const body = new URLSearchParams(formParams).toString();

	const response = await deps.httpClient(url, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body,
	});
	if (!response.ok) {
		return err(
			federationError(
				FederationErrorCode.NotFound,
				`Trust mark status check failed with status ${response.status}`,
			),
		);
	}

	const responseBody = await response.text();

	if (args.verify) {
		const ecResult = await fetchEntityConfiguration(eidResult.value, {
			httpClient: deps.httpClient,
		});
		if (!ecResult.ok) return ecResult;

		const ecDecoded = decodeEntityStatement(ecResult.value);
		if (!ecDecoded.ok) return ecDecoded;

		const ecPayload = ecDecoded.value.payload as Record<string, unknown>;
		const jwksResult = extractJwks(ecPayload);
		if (!jwksResult.ok) return jwksResult;

		const verified = await verifyTrustMarkStatusResponse(responseBody, jwksResult.value);
		if (!verified.ok) return verified;

		return ok(deps.formatter.format(verified.value));
	}

	const decoded = decodeEntityStatement(responseBody);
	if (decoded.ok) {
		return ok(deps.formatter.format(decoded.value.payload));
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(responseBody);
	} catch {
		return ok(deps.formatter.format({ response: responseBody }));
	}

	return ok(deps.formatter.format(parsed));
}

export function register(program: Command, deps: TrustMarkStatusDeps): void {
	program
		.command("trust-mark-status")
		.description("Check trust mark status at an entity")
		.argument("<entity-id>", "Entity hosting the trust mark status endpoint")
		.option("--trust-mark <jwt>", "Trust mark JWT to check")
		.option("--subject <url>", "Subject entity ID (use with --trust-mark-id)")
		.option("--trust-mark-id <id>", "Trust mark type ID (use with --subject)")
		.option("--verify", "Verify the response JWT signature", false)
		.action(
			async (
				entityIdArg: string,
				opts: {
					trustMark?: string;
					subject?: string;
					trustMarkId?: string;
					verify: boolean;
				},
			) => {
				const result = await handler(
					{
						entityId: entityIdArg,
						trustMark: opts.trustMark,
						subject: opts.subject,
						trustMarkId: opts.trustMarkId,
						verify: opts.verify,
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
