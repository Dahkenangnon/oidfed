import {
	decodeEntityConfiguration,
	err,
	FederationErrorCode,
	federationError,
	fetchEntityConfiguration,
	fetchSubordinateEvents,
	type HttpClient,
	type JWKSet,
	JWKSetSchema,
	ok,
	type Result,
	verifyEntityStatement,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface SubordinateEventsDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly readFile: (path: string) => Promise<string>;
}

export interface SubordinateEventsArgs {
	readonly entityId: string;
	readonly subject: string;
	readonly jwksFile: string;
	readonly clientAssertionFile?: string | undefined;
}

export async function handler(
	args: SubordinateEventsArgs,
	deps: SubordinateEventsDeps,
): Promise<Result<string>> {
	const issuer = parseEntityIdOrError(args.entityId);
	if (!issuer.ok) return issuer;
	const subject = parseEntityIdOrError(args.subject);
	if (!subject.ok) return subject;
	let keys: JWKSet;
	let clientAssertion: string | undefined;
	try {
		keys = JWKSetSchema.parse(JSON.parse(await deps.readFile(args.jwksFile)));
		if (args.clientAssertionFile)
			clientAssertion = (await deps.readFile(args.clientAssertionFile)).trim();
	} catch {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Cannot read a valid pinned JWKS or client assertion file",
			),
		);
	}
	const ec = await fetchEntityConfiguration(issuer.value, { httpClient: deps.httpClient });
	if (!ec.ok) return ec;
	const verified = await verifyEntityStatement(ec.value, keys);
	if (!verified.ok) return verified;
	const decoded = decodeEntityConfiguration(ec.value);
	if (!decoded.ok) return decoded;
	const payload = decoded.value.payload;
	if (payload.iss !== (issuer.value as string) || payload.sub !== (issuer.value as string)) {
		return err(
			federationError(
				FederationErrorCode.InvalidIssuer,
				"Entity Configuration does not match the requested authority",
			),
		);
	}
	const endpoint = payload.metadata?.federation_entity?.federation_subordinate_events_endpoint;
	if (typeof endpoint !== "string") {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Authority does not advertise federation_subordinate_events_endpoint",
			),
		);
	}
	const result = await fetchSubordinateEvents(endpoint, subject.value, {
		issuer: issuer.value,
		issuerJwks: keys,
		httpClient: deps.httpClient,
		...(clientAssertion !== undefined ? { clientAssertion } : {}),
	});
	if (!result.ok) return result;
	return ok(deps.formatter.format(result.value));
}

export function register(program: Command, deps: SubordinateEventsDeps): void {
	program
		.command("subordinate-events")
		.description("Fetch and verify an authority's recorded subordinate history")
		.argument("<entity-id>", "Issuing authority Entity Identifier")
		.argument("<subject>", "Immediate Subordinate Entity Identifier")
		.requiredOption("--jwks-file <path>", "Pinned authority public JWKS JSON file")
		.option(
			"--client-assertion-file <path>",
			"Client assertion JWT with the authority Entity Identifier as audience",
		)
		.action(
			async (
				entityId: string,
				subject: string,
				opts: { jwksFile: string; clientAssertionFile?: string },
			) => {
				const result = await handler(
					{
						entityId,
						subject,
						jwksFile: opts.jwksFile,
						clientAssertionFile: opts.clientAssertionFile,
					},
					deps,
				);
				if (result.ok) process.stdout.write(`${result.value}\n`);
				else {
					deps.logger.error(result.error.description);
					process.exitCode = 1;
				}
			},
		);
}
