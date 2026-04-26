import {
	decodeEntityStatement,
	err,
	FederationErrorCode,
	federationError,
	fetchEntityConfiguration,
	fetchTrustMarkStatus,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { discoverEndpoint } from "../util/discover-endpoint.js";
import { extractJwks, parseEntityIdOrError } from "../util/entity-id.js";
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
	readonly trustMarkType?: string | undefined;
	readonly verify: boolean;
	readonly statusEndpoint?: string | undefined;
}

export async function handler(
	args: TrustMarkStatusArgs,
	deps: TrustMarkStatusDeps,
): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;

	const hasTrustMark = !!args.trustMark;
	const hasSubjectType = !!args.subject && !!args.trustMarkType;

	if (!hasTrustMark && !hasSubjectType) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Either --trust-mark or both --subject and --trust-mark-type are required",
			),
		);
	}
	if (hasTrustMark && hasSubjectType) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Cannot use --trust-mark together with --subject/--trust-mark-type",
			),
		);
	}

	let endpoint: string;
	if (args.statusEndpoint) {
		endpoint = args.statusEndpoint;
	} else {
		const epResult = await discoverEndpoint(
			eidResult.value,
			"federation_trust_mark_status_endpoint",
			deps.httpClient,
		);
		if (!epResult.ok) return epResult;
		endpoint = epResult.value;
	}

	// JWT mode: route through fetchTrustMarkStatus when --verify is set, since
	// the core helper enforces HTTPS, no-fragment, Content-Type, typ-header,
	// and signature verification against the issuer's JWKS.
	if (hasTrustMark && args.verify) {
		const ecResult = await fetchEntityConfiguration(eidResult.value, {
			httpClient: deps.httpClient,
		});
		if (!ecResult.ok) return ecResult;
		const ecDecoded = decodeEntityStatement(ecResult.value);
		if (!ecDecoded.ok) return ecDecoded;
		const jwksResult = extractJwks(ecDecoded.value.payload as Record<string, unknown>);
		if (!jwksResult.ok) return jwksResult;

		deps.logger.info(`POSTing trust mark to ${endpoint} (verifying response)`);
		const statusResult = await fetchTrustMarkStatus(
			endpoint,
			args.trustMark as string,
			jwksResult.value,
			{
				httpClient: deps.httpClient,
			},
		);
		if (!statusResult.ok) return statusResult;
		return ok(deps.formatter.format(statusResult.value));
	}

	// Non-verify or sub+type mode: raw POST routed through the shared httpClient
	// (preserves SSRF / timeout policy supplied by createHttpClient).
	deps.logger.info(`POSTing to ${endpoint}`);
	const formParams = hasTrustMark
		? { trust_mark: args.trustMark as string }
		: { sub: args.subject as string, trust_mark_type: args.trustMarkType as string };
	const body = new URLSearchParams(formParams).toString();

	const response = await deps.httpClient(endpoint, {
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
		.description("Check the status of a Trust Mark at its issuer")
		.argument("<entity-id>", "Trust Mark Issuer entity ID")
		.option("--trust-mark <jwt>", "Trust Mark JWT to check")
		.option("--subject <url>", "Subject entity ID (use with --trust-mark-type)")
		.option("--trust-mark-type <id>", "Trust Mark type identifier (use with --subject)")
		.option("--verify", "Verify the response JWT signature against the issuer's JWKS", false)
		.option(
			"--status-endpoint <url>",
			"Override federation_trust_mark_status_endpoint discovery (advanced)",
		)
		.action(
			async (
				entityIdArg: string,
				opts: {
					trustMark?: string;
					subject?: string;
					trustMarkType?: string;
					verify: boolean;
					statusEndpoint?: string;
				},
			) => {
				const result = await handler(
					{
						entityId: entityIdArg,
						trustMark: opts.trustMark,
						subject: opts.subject,
						trustMarkType: opts.trustMarkType,
						verify: opts.verify,
						statusEndpoint: opts.statusEndpoint,
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
