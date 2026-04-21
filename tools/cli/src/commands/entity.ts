import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	type HttpClient,
	ok,
	type Result,
	verifyEntityStatement,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { extractJwks, parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface EntityDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface EntityArgs {
	readonly entityId: string;
	readonly decode: boolean;
	readonly verify: boolean;
}

export async function handler(args: EntityArgs, deps: EntityDeps): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;
	const eid = eidResult.value;

	const result = await fetchEntityConfiguration(eid, {
		httpClient: deps.httpClient,
	});

	if (!result.ok) return result;

	if (args.verify) {
		// Self-verify: decode to get JWKS, then verify signature
		const decoded = decodeEntityStatement(result.value);
		if (!decoded.ok) return decoded;

		const payload = decoded.value.payload as Record<string, unknown>;
		const jwksResult = extractJwks(payload);
		if (!jwksResult.ok) return jwksResult;

		const verified = await verifyEntityStatement(result.value, jwksResult.value);
		if (!verified.ok) return verified;

		return ok(deps.formatter.format(verified.value.payload));
	}

	if (!args.decode) {
		return ok(deps.formatter.format(result.value));
	}

	const decoded = decodeEntityStatement(result.value);
	if (!decoded.ok) return decoded;

	return ok(deps.formatter.format(decoded.value.payload));
}

export function register(program: Command, deps: EntityDeps): void {
	program
		.command("entity")
		.description("Fetch and display an entity configuration")
		.argument("<entity-id>", "Entity identifier (URL)")
		.option("--decode", "Decode the JWT payload", false)
		.option("--verify", "Verify the JWT signature (implies decode)", false)
		.action(async (entityIdArg: string, opts: { decode: boolean; verify: boolean }) => {
			const result = await handler(
				{ entityId: entityIdArg, decode: opts.decode, verify: opts.verify },
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
