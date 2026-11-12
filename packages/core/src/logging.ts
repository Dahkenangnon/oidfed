import type { Logger } from "./types.js";

const guarded = new WeakMap<Logger, Logger>();

/** Keep host logging failures from changing protocol behavior. Library logs contain messages only. */
export function safeLogger(logger: Logger | undefined): Logger | undefined {
	if (!logger) return undefined;
	let result = guarded.get(logger);
	if (!result) {
		const emit = (level: keyof Logger) => (message: string) => {
			try {
				void Promise.resolve(logger[level](message)).catch(() => {});
			} catch {
				// Logging is optional and must not change protocol results.
			}
		};
		result = { debug: emit("debug"), info: emit("info"), warn: emit("warn"), error: emit("error") };
		guarded.set(logger, result);
	}
	return result;
}
