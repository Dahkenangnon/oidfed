import {
	err,
	federationError,
	generateSigningKey,
	InternalErrorCode,
	ok,
	type Result,
	SUPPORTED_ALGORITHMS,
	type SupportedAlgorithm,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import type { Logger } from "../util/logger.js";

export interface KeygenDeps {
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface KeygenArgs {
	readonly algorithm: string;
	readonly publicOnly: boolean;
}

export async function handler(args: KeygenArgs, deps: KeygenDeps): Promise<Result<string>> {
	if (!(SUPPORTED_ALGORITHMS as readonly string[]).includes(args.algorithm)) {
		return err(
			federationError(
				InternalErrorCode.UnsupportedAlg,
				`Unsupported algorithm: ${args.algorithm}. Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`,
			),
		);
	}

	const keyPair = await generateSigningKey(args.algorithm as SupportedAlgorithm);

	const output = args.publicOnly
		? { keys: [keyPair.publicKey] }
		: { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };

	return ok(deps.formatter.format(output));
}

export function register(program: Command, deps: KeygenDeps): void {
	program
		.command("keygen")
		.description("Generate a signing key pair")
		.option("-a, --algorithm <alg>", "Signing algorithm", "ES256")
		.option("--public-only", "Output only the public key as a JWKS", false)
		.action(async (opts: { algorithm: string; publicOnly: boolean }) => {
			const result = await handler(
				{ algorithm: opts.algorithm, publicOnly: opts.publicOnly },
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
