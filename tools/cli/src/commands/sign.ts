import {
	err,
	FederationErrorCode,
	federationError,
	InternalErrorCode,
	ok,
	type Result,
	signEntityStatement,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import type { Logger } from "../util/logger.js";

export interface SignDeps {
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly readFile: (path: string) => Promise<string>;
}

export interface SignArgs {
	readonly payloadPath: string;
	readonly keyPath: string;
	readonly algorithm?: string | undefined;
}

export async function handler(args: SignArgs, deps: SignDeps): Promise<Result<string>> {
	let payloadRaw: string;
	try {
		payloadRaw = await deps.readFile(args.payloadPath);
	} catch {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Cannot read payload file: ${args.payloadPath}`,
			),
		);
	}

	let keyRaw: string;
	try {
		keyRaw = await deps.readFile(args.keyPath);
	} catch {
		return err(
			federationError(FederationErrorCode.InvalidRequest, `Cannot read key file: ${args.keyPath}`),
		);
	}

	let payload: Record<string, unknown>;
	try {
		payload = JSON.parse(payloadRaw) as Record<string, unknown>;
	} catch {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Payload file is not valid JSON"),
		);
	}

	let privateKey: Record<string, unknown>;
	try {
		privateKey = JSON.parse(keyRaw) as Record<string, unknown>;
	} catch {
		return err(federationError(FederationErrorCode.InvalidRequest, "Key file is not valid JSON"));
	}

	try {
		const jwt = await signEntityStatement(
			payload,
			privateKey as Parameters<typeof signEntityStatement>[1],
			args.algorithm ? { alg: args.algorithm } : undefined,
		);
		return ok(jwt);
	} catch (e) {
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				`Signing failed: ${e instanceof Error ? e.message : String(e)}`,
			),
		);
	}
}

export function register(program: Command, deps: SignDeps): void {
	program
		.command("sign")
		.description("Sign a JSON payload as a JWT entity statement")
		.requiredOption("-p, --payload <path>", "Path to JSON payload file")
		.requiredOption("-k, --key <path>", "Path to JWK private key file")
		.option("-a, --algorithm <alg>", "Signing algorithm (default: from key)")
		.action(async (opts: { payload: string; key: string; algorithm?: string | undefined }) => {
			const result = await handler(
				{ payloadPath: opts.payload, keyPath: opts.key, algorithm: opts.algorithm },
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
