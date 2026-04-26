import {
	decodeEntityStatement,
	fetchSubordinateStatement,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { discoverEndpoint } from "../util/discover-endpoint.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
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
	readonly fetchEndpoint?: string | undefined;
}

export async function handler(args: FetchArgs, deps: FetchDeps): Promise<Result<string>> {
	const issuerResult = parseEntityIdOrError(args.issuer);
	if (!issuerResult.ok) return issuerResult;

	const subjectResult = parseEntityIdOrError(args.subject);
	if (!subjectResult.ok) return subjectResult;

	let endpoint: string;
	if (args.fetchEndpoint) {
		endpoint = args.fetchEndpoint;
	} else {
		const epResult = await discoverEndpoint(
			issuerResult.value,
			"federation_fetch_endpoint",
			deps.httpClient,
		);
		if (!epResult.ok) return epResult;
		endpoint = epResult.value;
	}

	deps.logger.info(`Fetching subordinate statement from ${endpoint}`);
	const ssResult = await fetchSubordinateStatement(endpoint, subjectResult.value, {
		httpClient: deps.httpClient,
	});
	if (!ssResult.ok) return ssResult;

	if (!args.decode) {
		return ok(deps.formatter.format(ssResult.value));
	}

	const decoded = decodeEntityStatement(ssResult.value);
	if (!decoded.ok) return decoded;

	return ok(deps.formatter.format(decoded.value.payload));
}

export function register(program: Command, deps: FetchDeps): void {
	program
		.command("fetch")
		.description("Fetch a subordinate statement from an authority")
		.requiredOption("-i, --issuer <url>", "Issuer (authority) entity ID")
		.requiredOption("-s, --subject <url>", "Subject entity ID")
		.option("--fetch-endpoint <url>", "Override the federation_fetch_endpoint discovery (advanced)")
		.option("--decode", "Decode the JWT payload", false)
		.action(
			async (opts: {
				issuer: string;
				subject: string;
				decode: boolean;
				fetchEndpoint?: string;
			}) => {
				const result = await handler(
					{
						issuer: opts.issuer,
						subject: opts.subject,
						decode: opts.decode,
						fetchEndpoint: opts.fetchEndpoint,
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
