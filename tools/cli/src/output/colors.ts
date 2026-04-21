import chalk from "chalk";

export const colors = {
	// JSON tokens
	key: (s: string) => chalk.cyan(s),
	string: (s: string) => chalk.green(s),
	number: (s: string) => chalk.yellow(s),
	boolean: (s: string) => chalk.magenta(s),
	null: (s: string) => chalk.dim(s),

	// Table
	header: (s: string) => chalk.bold.white(s),
	separator: (s: string) => chalk.dim(s),
	label: (s: string) => chalk.cyan(s),

	// Status
	ok: (s: string) => chalk.green(s),
	warn: (s: string) => chalk.yellow(s),
	error: (s: string) => chalk.red(s),

	// JWT segments
	jwtHeader: (s: string) => chalk.cyan(s),
	jwtPayload: (s: string) => chalk.green(s),
	jwtSignature: (s: string) => chalk.dim(s),

	// Logger levels
	info: (s: string) => chalk.blue(s),
	debug: (s: string) => chalk.dim(s),
} as const;

export function isCompactJwt(data: unknown): data is string {
	if (typeof data !== "string") return false;
	const parts = data.split(".");
	return parts.length === 3 && parts.every((p) => p.length > 0);
}
