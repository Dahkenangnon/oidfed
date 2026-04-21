import {
	decodeEntityStatement,
	err,
	FederationErrorCode,
	federationError,
	fetchEntityConfiguration,
	type HttpClient,
	type JWKSet,
	ok,
	type Result,
	verifyEntityStatement,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { extractJwks, parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface VerifyDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly readFile: (path: string) => Promise<string>;
}

export interface VerifyArgs {
	readonly jwt: string;
	readonly jwksFile?: string | undefined;
	readonly entityId?: string | undefined;
}

export async function handler(args: VerifyArgs, deps: VerifyDeps): Promise<Result<string>> {
	// Resolve JWKS from one of three sources
	let jwks: JWKSet;

	if (args.jwksFile) {
		let raw: string;
		try {
			raw = await deps.readFile(args.jwksFile);
		} catch {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					`Cannot read JWKS file: ${args.jwksFile}`,
				),
			);
		}
		try {
			jwks = JSON.parse(raw) as JWKSet;
		} catch {
			return err(
				federationError(FederationErrorCode.InvalidRequest, "JWKS file is not valid JSON"),
			);
		}
	} else {
		// Determine entity ID: from --entity-id or from JWT iss claim
		let eid: string;
		if (args.entityId) {
			eid = args.entityId;
		} else {
			const decoded = decodeEntityStatement(args.jwt);
			if (!decoded.ok) return decoded;
			eid = (decoded.value.payload as Record<string, unknown>).iss as string;
			if (!eid) {
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"JWT has no iss claim; specify --jwks-file or --entity-id",
					),
				);
			}
		}

		const validEidResult = parseEntityIdOrError(eid);
		if (!validEidResult.ok) return validEidResult;
		const validEid = validEidResult.value;

		const ecResult = await fetchEntityConfiguration(validEid, {
			httpClient: deps.httpClient,
		});
		if (!ecResult.ok) return ecResult;

		const ecDecoded = decodeEntityStatement(ecResult.value);
		if (!ecDecoded.ok) return ecDecoded;

		const payload = ecDecoded.value.payload as Record<string, unknown>;
		const jwksResult = extractJwks(payload);
		if (!jwksResult.ok) return jwksResult;
		jwks = jwksResult.value;
	}

	const verified = await verifyEntityStatement(args.jwt, jwks);
	if (!verified.ok) return verified;

	return ok(
		deps.formatter.format({ header: verified.value.header, payload: verified.value.payload }),
	);
}

export function register(program: Command, deps: VerifyDeps): void {
	program
		.command("verify")
		.description("Verify a JWT signature against a JWKS")
		.argument("<jwt>", "JWT string to verify")
		.option("--jwks-file <path>", "Path to JWKS JSON file")
		.option("--entity-id <url>", "Fetch JWKS from this entity's configuration")
		.action(async (jwt: string, opts: { jwksFile?: string; entityId?: string }) => {
			const result = await handler({ jwt, jwksFile: opts.jwksFile, entityId: opts.entityId }, deps);
			if (result.ok) {
				process.stdout.write(`${result.value}\n`);
			} else {
				deps.logger.error(result.error.description);
				process.exitCode = 1;
			}
		});
}
