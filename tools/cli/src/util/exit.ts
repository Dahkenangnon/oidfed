import type { Result } from "@oidfed/core";

/** Exit codes: 0 = success, 1 = federation error, 2 = usage error */
export const ExitCode = {
	OK: 0,
	FEDERATION_ERROR: 1,
	USAGE_ERROR: 2,
} as const;

export type ExitCode = (typeof ExitCode)[keyof typeof ExitCode];

export function resultToExitCode(result: Result<unknown>): ExitCode {
	return result.ok ? ExitCode.OK : ExitCode.FEDERATION_ERROR;
}
