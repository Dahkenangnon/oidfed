import {
	decodeEntityStatement,
	FederationEndpoint,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { normalizeEntityId, parseEntityIdOrError } from "../util/entity-id.js";
import { fetchTextOrError } from "../util/http.js";
import type { Logger } from "../util/logger.js";

export interface FetchDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface FetchArgs {
	readonly issuer: string;
	readonly subject: string;
	readonly decode: boolean;
}

export async function handler(args: FetchArgs, deps: FetchDeps): Promise<Result<string>> {
	const issuerResult = parseEntityIdOrError(args.issuer);
	if (!issuerResult.ok) return issuerResult;
	const issuerBase = normalizeEntityId(args.issuer);

	const subjectResult = parseEntityIdOrError(args.subject);
	if (!subjectResult.ok) return subjectResult;

	const url = `${issuerBase}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(args.subject)}`;
	deps.logger.info(`Fetching ${url}`);

	const bodyResult = await fetchTextOrError(deps.httpClient, url, "Fetch failed");
	if (!bodyResult.ok) return bodyResult;

	if (!args.decode) {
		return ok(deps.formatter.format(bodyResult.value));
	}

	const decoded = decodeEntityStatement(bodyResult.value);
	if (!decoded.ok) return decoded;

	return ok(deps.formatter.format(decoded.value.payload));
}

export function register(program: Command, deps: FetchDeps): void {
	program
		.command("fetch")
		.description("Fetch a subordinate statement from an authority")
		.requiredOption("-i, --issuer <url>", "Issuer (authority) entity ID")
		.requiredOption("-s, --subject <url>", "Subject entity ID")
		.option("--decode", "Decode the JWT payload", false)
		.action(async (opts: { issuer: string; subject: string; decode: boolean }) => {
			const result = await handler(
				{ issuer: opts.issuer, subject: opts.subject, decode: opts.decode },
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
