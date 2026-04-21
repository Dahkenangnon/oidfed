import { readFile } from "node:fs/promises";
import { Command } from "commander";
import * as chainCmd from "./commands/chain.js";
import * as decodeCmd from "./commands/decode.js";
import * as entityCmd from "./commands/entity.js";
import * as expiryCmd from "./commands/expiry.js";
import * as fetchCmd from "./commands/fetch.js";
import * as healthCmd from "./commands/health.js";
import * as keygenCmd from "./commands/keygen.js";
import * as listCmd from "./commands/list.js";
import * as resolveCmd from "./commands/resolve.js";
import * as signCmd from "./commands/sign.js";
import * as trustMarkListCmd from "./commands/trust-mark-list.js";
import * as trustMarkStatusCmd from "./commands/trust-mark-status.js";
import * as validateCmd from "./commands/validate.js";
import * as verifyCmd from "./commands/verify.js";
import { DEFAULT_CONFIG, loadConfig } from "./config.js";
import { createFormatter } from "./output/index.js";
import { ExitCode } from "./util/exit.js";
import { createHttpClient } from "./util/http.js";
import { createLogger } from "./util/logger.js";

export { type Config, DEFAULT_CONFIG, loadConfig } from "./config.js";
export { createFormatter, type OutputFormatter } from "./output/index.js";
export { ExitCode, resultToExitCode } from "./util/exit.js";
export { createHttpClient } from "./util/http.js";
export { createLogger, type Logger } from "./util/logger.js";

export interface ProgramOptions {
	readonly json?: boolean | undefined;
	readonly quiet?: boolean;
	readonly verbose?: boolean;
	readonly config?: string;
}

export function createProgram(): Command {
	const program = new Command();

	program
		.name("oidfed")
		.description("OpenID Federation CLI — fetch, resolve, validate trust chains")
		.version("0.1.0")
		.option("--json", "Output raw JSON (machine-readable, suitable for piping to jq)")
		.option("-q, --quiet", "Suppress informational output", false)
		.option("-v, --verbose", "Enable debug output", false)
		.option("-c, --config <path>", "Path to config file");

	return program;
}

export async function run(argv: string[]): Promise<number> {
	const program = createProgram();
	program.parseOptions(argv);

	const opts = program.opts<ProgramOptions>();

	const configResult = await loadConfig(opts.config);
	const config = configResult.ok ? configResult.value : DEFAULT_CONFIG;

	const formatter = createFormatter({ json: opts.json });
	const logger = createLogger({
		quiet: opts.quiet ?? false,
		verbose: opts.verbose ?? false,
	});
	const httpClient = createHttpClient(config.http_timeout_ms);
	const fileReader = (path: string) => readFile(path, "utf-8");

	entityCmd.register(program, { httpClient, formatter, logger });
	decodeCmd.register(program, { formatter, logger });
	keygenCmd.register(program, { formatter, logger });
	signCmd.register(program, { formatter, logger, readFile: fileReader });
	chainCmd.register(program, { httpClient, formatter, logger, config });
	resolveCmd.register(program, { httpClient, formatter, logger, config });
	validateCmd.register(program, { httpClient, formatter, logger, config });
	expiryCmd.register(program, { httpClient, formatter, logger, config });
	fetchCmd.register(program, { httpClient, formatter, logger });
	listCmd.register(program, { httpClient, formatter, logger });
	trustMarkStatusCmd.register(program, { httpClient, formatter, logger });
	trustMarkListCmd.register(program, { httpClient, formatter, logger });
	healthCmd.register(program, { httpClient, formatter, logger, readFile: fileReader });
	verifyCmd.register(program, { httpClient, formatter, logger, readFile: fileReader });

	try {
		await program.parseAsync(argv, { from: "user" });
		return process.exitCode ? Number(process.exitCode) : ExitCode.OK;
	} catch {
		return ExitCode.FEDERATION_ERROR;
	}
}
