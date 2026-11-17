/** Guard the analysis boundary and fail-closed scanner inputs. */

import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, mkdir, copyFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { packages, sources, isPackageSource } from "./scope.mjs";
import { registryPackages, cycloneDxInput, productionGraph } from "./dependency-graph.mjs";
import { cycleKey } from "./run.mjs";
import config from "./eslint.config.mjs";
import dependencies from "./dependencies.config.mjs";
import knip from "./knip.config.mjs";
import { bin } from "./install.mjs";

test("source tools share the five-package allowlist", async () => {
	assert.deepEqual(packages, ["core", "authority", "leaf", "oidc", "wallet"]);
	assert.deepEqual(
		config[0].files,
		sources.map((path) => `${path}/**/*.{ts,tsx,js,jsx,mjs,cjs}`),
	);
	assert.deepEqual(
		config[1].files,
		sources.map((path) => `${path}/**/*.ts`),
	);
	assert.deepEqual(
		Object.keys(knip.workspaces).filter((path) => path !== "."),
		packages.map((name) => `packages/${name}`),
	);
	const codeql = await readFile(new URL("./codeql.yml", import.meta.url), "utf8");
	assert.deepEqual(
		codeql
			.split("\n")
			.filter((line) => line.startsWith("  - packages/"))
			.map((line) => line.slice(4)),
		sources,
	);
	for (const path of sources) {
		assert.ok(isPackageSource(`${path}/index.ts`));
		assert.equal(new RegExp(dependencies.options.doNotFollow.path).test(`${path}/index.ts`), false);
	}
	for (const path of [
		"apps/home/src/index.ts",
		"tools/cli/src/index.ts",
		"packages/other/src/index.ts",
		"packages/core/src/../../../tools/cli/src/index.ts",
	])
		assert.equal(isPackageSource(path), false);
});

test("dependency extraction keeps exact transitive and optional versions, not dev or app packages", () => {
	const graph = [
		{
			name: "@oidfed/authority",
			dependencies: {
				"@oidfed/core": {
					version: "link:../core",
					dependencies: {
						jose: { version: "6.2.13" },
						shared: {
							version: "1.0.0(peer@2.0.0)",
							optionalDependencies: { optional: { version: "3.0.0" } },
						},
					},
				},
			},
			devDependencies: { "app-only": { version: "99.0.0" } },
		},
	];
	assert.deepEqual(
		registryPackages(graph).map(({ name, version }) => `${name}@${version}`),
		["jose@6.2.13", "optional@3.0.0", "shared@1.0.0"],
	);
	assert.throws(() => registryPackages([{ name: "@oidfed/explorer" }]), /out-of-scope/);
	assert.throws(
		() =>
			registryPackages([{ name: "@oidfed/core", dependencies: { bad: { version: "latest" } } }]),
		/resolved version/,
	);
	assert.throws(() => cycloneDxInput([]), /empty/);
	assert.equal(
		cycloneDxInput([{ name: "@scope/name", version: "1.2.3" }]).components[0].purl,
		"pkg:npm/%40scope/name@1.2.3",
	);
});

test("known cycles cannot conceal a new edge or a different directed cycle", () => {
	assert.equal(cycleKey(["a", "b", "c"]), cycleKey(["b", "c", "a"]));
	assert.notEqual(cycleKey(["a", "b", "c"]), cycleKey(["a", "c", "b"]));
	assert.notEqual(cycleKey(["a", "b", "c"]), cycleKey(["a", "b", "c", "new"]));
});

test("pnpm produces the same scoped graph without an installation", async () => {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-lockfile-"));
	try {
		for (const file of [
			"package.json",
			"pnpm-lock.yaml",
			"pnpm-workspace.yaml",
			...packages.map((name) => `packages/${name}/package.json`),
		]) {
			const directory = join(temporary, file, "..");
			await mkdir(directory, { recursive: true });
			await copyFile(new URL(`../../${file}`, import.meta.url), join(temporary, file));
		}
		assert.deepEqual(productionGraph(temporary), productionGraph());
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

test("the secret scanner detects a canary and redacts its value", async () => {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-scanner-positive-"));
	try {
		const { writeFile } = await import("node:fs/promises");
		const canary = [
			"ghp_",
			randomBytes(27)
				.toString("base64")
				.replace(/[^a-zA-Z0-9]/g, "Q"),
		].join("");
		await mkdir(join(temporary, "dist"));
		await writeFile(join(temporary, "dist/index.js"), `const github_token = "${canary}";`);
		const report = join(temporary, "findings.json");
		const result = spawnSync(
			join(bin, "gitleaks"),
			[
				"dir",
				temporary,
				"--redact=100",
				"--no-banner",
				"--config",
				"scripts/security/gitleaks.toml",
				"--report-format",
				"json",
				"--report-path",
				report,
			],
			{ encoding: "utf8" },
		);
		if (result.error) throw result.error;
		assert.equal(result.status, 1, "a packaged JS file containing a canary must fail the scan");
		assert.equal(`${result.stdout}${result.stderr}`.includes(canary), false);
		const findings = await readFile(report, "utf8");
		assert.ok(findings.includes("REDACTED"));
		assert.equal(findings.includes(canary), false);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});
