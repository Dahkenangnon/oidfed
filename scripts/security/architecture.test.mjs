/** Exercise architecture rules against deliberately invalid miniature packages. */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import config from "./dependencies.config.mjs";
import { root } from "./scope.mjs";

test("architecture rules reject Node built-ins and private cross-package imports", async () => {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-architecture-"));
	try {
		for (const name of ["core", "wallet", "oidc", "crypto"])
			await mkdir(join(temporary, `packages/${name}/src`), { recursive: true });
		await writeFile(
			join(temporary, "packages/core/src/index.ts"),
			'import {backend} from "../../crypto/src/web.js"; import {existsSync} from "node:fs"; import {value} from "../../wallet/src/private.js"; export const result = [existsSync, value, backend];',
		);
		await writeFile(join(temporary, "packages/wallet/src/private.ts"), "export const value = 1;");
		await writeFile(join(temporary, "packages/crypto/src/web.ts"), "export const backend = {};");
		await mkdir(join(temporary, "apps/sample/src"), { recursive: true });
		await writeFile(
			join(temporary, "apps/sample/src/index.ts"),
			'throw new Error("This application must not be analyzed");',
		);
		await writeFile(
			join(temporary, "packages/oidc/src/index.ts"),
			'import {value} from "../../wallet/src/private.js"; import {result} from "../../core/src/index.js"; import "../../../apps/sample/src/index.js"; export const combined = [value, result];',
		);
		await writeFile(
			join(temporary, "tsconfig.json"),
			JSON.stringify({
				compilerOptions: { target: "ES2022", moduleResolution: "bundler", module: "ESNext" },
				include: ["packages"],
			}),
		);
		const fixtureConfig = {
			...config,
			options: { ...config.options, tsConfig: { fileName: "tsconfig.json" } },
		};
		await writeFile(join(temporary, "rules.json"), JSON.stringify(fixtureConfig));
		const result = spawnSync(
			join(root, "node_modules/.bin/depcruise"),
			["-c", "rules.json", "-T", "json", "packages/core/src", "packages/oidc/src"],
			{ cwd: temporary, encoding: "utf8" },
		);
		if (result.error) throw result.error;
		assert.ok([0, 1].includes(result.status), result.stderr);
		const report = JSON.parse(result.stdout);
		const rules = new Set(report.summary.violations.map((entry) => entry.rule.name));
		for (const rule of [
			"core-is-independent",
			"protocol-libraries-have-no-crypto-backend",
			"no-private-cross-package-imports",
			"web-runtime-only",
			"no-application-or-tool-imports",
		])
			assert.ok(rules.has(rule), `${rule} must detect its negative fixture`);
		assert.equal(
			report.summary.violations.some(
				(entry) =>
					entry.from === "packages/oidc/src/index.ts" && entry.to === "packages/core/src/index.ts",
			),
			false,
			"the public core entrypoint is allowed",
		);
		assert.ok(
			report.modules
				.filter((entry) => entry.source.startsWith("apps/"))
				.every((entry) => entry.dependencies.length === 0),
			"application implementations are not traversed",
		);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});
