/** Verify that the typed, regexp, and documentation rules catch their negative cases. */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { root } from "../../../scripts/security/scope.mjs";

test("security lint rules detect unsafe code in a scoped TypeScript project", async () => {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-lint-"));
	try {
		await mkdir(join(temporary, "packages/core/src"), { recursive: true });
		await writeFile(join(temporary, "package.json"), '{"private":true,"type":"module"}');
		await writeFile(
			join(temporary, "tsconfig.json"),
			JSON.stringify({
				compilerOptions: { strict: true, target: "ES2022", module: "ESNext" },
				include: ["packages"],
			}),
		);
		const configUrl = new URL("../../../scripts/security/eslint.config.mjs", import.meta.url).href;
		await writeFile(
			join(temporary, "eslint.config.mjs"),
			`import original from ${JSON.stringify(configUrl)}; export default original.map(item => ({...item, languageOptions: {...item.languageOptions, parserOptions: {...item.languageOptions.parserOptions, tsconfigRootDir: ${JSON.stringify(temporary)}}}}));`,
		);
		await writeFile(
			join(temporary, "packages/core/src/index.ts"),
			`
declare const input: any;
export const unsafe: string = input.token;
export function unsafeReturn(): string { return input; }
export function unsafeCall() { input(); }
function takesString(value: string) { return value; }
takesString(input);
Promise.resolve("lost");
if (Promise.resolve(true)) takesString("promise used as boolean");
export async function incorrectAwait() { await 42; }
export function missingCase(kind: "first" | "second") { switch (kind) { case "first": return 1; } }
export const unsafeRegexp = /(a+)+$/;
/** @param missing Incorrect parameter name. */
export function documented(actual: string) { return actual; }
`,
		);
		const result = spawnSync(
			join(root, "node_modules/.bin/eslint"),
			[
				"--no-config-lookup",
				"-c",
				"eslint.config.mjs",
				"--format",
				"json",
				"packages/core/src/index.ts",
			],
			{ cwd: temporary, encoding: "utf8" },
		);
		if (result.error) throw result.error;
		assert.equal(result.status, 1, result.stderr);
		const reports = JSON.parse(result.stdout);
		const rules = new Set(
			reports.flatMap((report) => report.messages.map((message) => message.ruleId)),
		);
		for (const rule of [
			"@typescript-eslint/no-unsafe-assignment",
			"@typescript-eslint/no-unsafe-member-access",
			"@typescript-eslint/no-unsafe-return",
			"@typescript-eslint/no-unsafe-call",
			"@typescript-eslint/no-unsafe-argument",
			"@typescript-eslint/no-floating-promises",
			"@typescript-eslint/no-misused-promises",
			"@typescript-eslint/await-thenable",
			"@typescript-eslint/switch-exhaustiveness-check",
			"regexp/no-super-linear-backtracking",
			"jsdoc/check-param-names",
		])
			assert.ok(rules.has(rule), `${rule} must catch its negative fixture: ${result.stdout}`);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});
