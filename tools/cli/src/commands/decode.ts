import { decodeEntityStatement, ok, type Result } from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import type { Logger } from "../util/logger.js";

export interface DecodeDeps {
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
}

export interface DecodeArgs {
	readonly jwt: string;
	readonly headerOnly: boolean;
}

export function handler(args: DecodeArgs, deps: DecodeDeps): Result<string> {
	const result = decodeEntityStatement(args.jwt);
	if (!result.ok) return result;

	const data = args.headerOnly ? result.value.header : result.value.payload;
	return ok(deps.formatter.format(data));
}

export function register(program: Command, deps: DecodeDeps): void {
	program
		.command("decode")
		.description("Decode a JWT entity statement without verification")
		.argument("<jwt>", "JWT string to decode")
		.option("--header", "Show only the JOSE header", false)
		.action((jwt: string, opts: { header: boolean }) => {
			const result = handler({ jwt, headerOnly: opts.header }, deps);
			if (result.ok) {
				process.stdout.write(`${result.value}\n`);
			} else {
				deps.logger.error(result.error.description);
				process.exitCode = 1;
			}
		});
}
