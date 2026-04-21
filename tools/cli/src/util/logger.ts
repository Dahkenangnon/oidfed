import { colors } from "../output/colors.js";

export interface LoggerOptions {
	readonly quiet: boolean;
	readonly verbose: boolean;
	readonly stderr?: Pick<NodeJS.WritableStream, "write">;
}

export interface Logger {
	info(msg: string): void;
	error(msg: string): void;
	debug(msg: string): void;
	warn(msg: string): void;
}

export function createLogger(opts: LoggerOptions): Logger {
	const stream = opts.stderr ?? process.stderr;
	const write = (prefix: string, msg: string) => {
		stream.write(`${prefix} ${msg}\n`);
	};

	return {
		info(msg: string) {
			if (!opts.quiet) write(colors.info("[info]"), msg);
		},
		error(msg: string) {
			write(colors.error("[error]"), msg);
		},
		debug(msg: string) {
			if (opts.verbose) write(colors.debug("[debug]"), msg);
		},
		warn(msg: string) {
			if (!opts.quiet) write(colors.warn("[warn]"), msg);
		},
	};
}
