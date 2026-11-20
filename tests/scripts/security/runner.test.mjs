/** Exercise tool discovery and machine-readable output through the security commands. */

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
	mkdtemp,
	mkdir,
	writeFile,
	copyFile,
	symlink,
	readFile,
	rm,
	access,
} from "node:fs/promises";
import { join, delimiter } from "node:path";
import { tmpdir } from "node:os";
import { root } from "../../../scripts/security/scope.mjs";

test("architecture reads analyzer JSON without package-manager warning output", async () => {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-runner-warning-"));
	try {
		await writeFile(
			join(temporary, "pnpm"),
			'#!/bin/sh\nprintf "Unsupported engine warning before analyzer JSON\\n"\nexit 1\n',
			{ mode: 0o755 },
		);
		const result = spawnSync(process.execPath, ["scripts/security/run.mjs", "architecture"], {
			cwd: root,
			env: { ...process.env, PATH: `${temporary}${delimiter}${process.env.PATH}` },
			encoding: "utf8",
		});
		assert.equal(result.status, 0, result.stderr);
		assert.match(result.stdout, /Architecture: \d+ modules/);
		assert.doesNotMatch(result.stdout, /Unsupported engine warning/);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

async function scannerWorkspace(prefix = "oidfed-runner-scanner-") {
	const temporary = await mkdtemp(join(tmpdir(), prefix));
	const scripts = join(temporary, "scripts/security");
	await mkdir(scripts, { recursive: true });
	await mkdir(join(temporary, "node_modules"));
	await writeFile(join(temporary, "package.json"), '{"type":"module"}');
	for (const file of [
		"run.mjs",
		"scope.mjs",
		"install.mjs",
		"dependency-graph.mjs",
		"known-cycles.mjs",
		"lint.mjs",
		"eslint.config.mjs",
		"eslint-rules.mjs",
	])
		await copyFile(join(root, "scripts/security", file), join(scripts, file));
	await mkdir(join(temporary, "scripts/release"));
	await copyFile(join(root, "scripts/release/catalog.mjs"), join(temporary, "scripts/release/catalog.mjs"));
	for (const dependency of [
		"esbuild",
		"semver",
		"typescript",
		"yaml",
		"eslint",
		"typescript-eslint",
		"eslint-plugin-regexp",
		"eslint-plugin-jsdoc",
	])
		await symlink(
			join(root, "node_modules", dependency),
			join(temporary, "node_modules", dependency),
			"dir",
		);
	return temporary;
}

test("security lint scans all six packages, including JavaScript, and fails closed", async () => {
	const temporary = await scannerWorkspace();
	try {
		await writeFile(
			join(temporary, "tsconfig.json"),
			JSON.stringify({
				compilerOptions: { strict: true, target: "ES2022", module: "ESNext" },
				include: ["packages"],
			}),
		);
		for (const name of ["core", "authority", "leaf", "oidc", "wallet", "crypto"]) {
			const directory = join(temporary, "packages", name, "src");
			await mkdir(directory, { recursive: true });
			await writeFile(join(directory, "index.ts"), "export const safe = 1;\n");
		}
		await mkdir(join(temporary, "apps/example/src"), { recursive: true });
		await writeFile(join(temporary, "apps/example/src/index.ts"), "invalid syntax (((");
		const lint = () =>
			spawnSync(process.execPath, ["scripts/security/run.mjs", "lint"], {
				cwd: temporary,
				encoding: "utf8",
			});
		let result = lint();
		assert.equal(result.status, 0, result.stderr);
		assert.match(result.stdout, /6 source files across all six/);
		const bad = join(temporary, "packages/core/src/trust-chain/fetch.js");
		await mkdir(join(temporary, "packages/core/src/trust-chain"));
		await writeFile(
			bad,
			"fetch('https://entity.example');\nglobalThis.fetch('https://entity.example');\n",
		);
		result = lint();
		assert.notEqual(result.status, 0);
		assert.equal(result.stdout.match(/protocol\/no-unbounded-fetch/g)?.length, 2);
		await rm(bad);
		const source = join(temporary, "packages/core/src/index.ts");
		await writeFile(
			source,
			`
export {};
declare const parameters: URLSearchParams;
declare const registry: Record<string, () => void>;
const key = (parameters.get as (name: string) => string)("method");
registry[key]();
const box: Record<string, string> = {};
box.method = parameters.get("method")!;
registry[box["method"]]();
(Function as typeof Function)("return 1");
`,
		);
		result = lint();
		assert.notEqual(result.status, 0);
		assert.equal(result.stdout.match(/protocol\/no-inherited-auth-dispatch/g)?.length, 2);
		assert.equal(result.stdout.match(/protocol\/no-wrapped-function-constructor/g)?.length, 1);
		await writeFile(source, "export const invalid = (((");
		result = lint();
		assert.notEqual(result.status, 0);
		assert.match(result.stdout, /Parsing error/);
		await writeFile(source, "export const safe = 1;\n");
		await rm(join(temporary, "packages/wallet/src/index.ts"));
		result = lint();
		assert.notEqual(result.status, 0, "an empty package cannot silently pass");
		await rm(join(temporary, "scripts/security/eslint.config.mjs"));
		assert.notEqual(lint().status, 0, "a missing scanner configuration cannot silently pass");
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

test("the runner executes and rejects unknown commands in encoded checkout paths", async () => {
	const temporary = await scannerWorkspace("oidfed runner é-");
	try {
		const result = spawnSync(process.execPath, ["scripts/security/run.mjs", "unknown-command"], {
			cwd: temporary,
			encoding: "utf8",
		});
		assert.notEqual(
			result.status,
			0,
			"the command must execute instead of silently returning success",
		);
		assert.match(result.stderr, /Choose lint/);
		const imported = spawnSync(
			process.execPath,
			["--input-type=module", "-e", 'await import("./scripts/security/run.mjs")'],
			{
				cwd: temporary,
				encoding: "utf8",
			},
		);
		assert.equal(imported.status, 0, imported.stderr);
		assert.equal(imported.stdout, "", "importing the runner does not execute a check");
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

test("the installer executes in encoded checkout paths without executing on import", async () => {
	const temporary = await scannerWorkspace("oidfed installer é-");
	try {
		const probe =
			'globalThis.fetch = async () => { throw Error("installer download reached"); }; const module = "./scripts/security/install.mjs"; if (process.env.START_INSTALLER) process.argv[1] = process.cwd() + "/scripts/security/install.mjs"; await import(module);';
		for (const start of [false, true]) {
			const result = spawnSync(process.execPath, ["--input-type=module", "-e", probe], {
				cwd: temporary,
				env: { ...process.env, ...(start ? { START_INSTALLER: "1" } : {}) },
				encoding: "utf8",
			});
			if (start) {
				assert.notEqual(result.status, 0);
				assert.match(result.stderr, /installer download reached/);
			} else {
				assert.equal(result.status, 0, result.stderr);
				assert.equal(result.stdout, "");
			}
		}
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

async function dependencyFixture(walletAtBase) {
	const temporary = await scannerWorkspace();
	await writeFile(join(temporary, "pnpm-workspace.yaml"), 'packages: ["packages/*"]\n');
	await writeFile(join(temporary, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters: {}\n");
	for (const name of ["core", "authority", "leaf", "oidc", "crypto", ...(walletAtBase ? ["wallet"] : [])]) {
		await mkdir(join(temporary, "packages", name), { recursive: true });
		await writeFile(
			join(temporary, "packages", name, "package.json"),
			JSON.stringify({ name: `@oidfed/${name}` }),
		);
	}
	await mkdir(join(temporary, "tools/cli"), { recursive: true });
	await writeFile(join(temporary, "tools/cli/package.json"), JSON.stringify({ name: "@oidfed/cli" }));
	const git = (...args) => {
		const result = spawnSync(
			"git",
			[
				"-c",
				"commit.gpgsign=false",
				"-c",
				"core.hooksPath=/dev/null",
				"-c",
				"user.name=Fixture",
				"-c",
				"user.email=fixture@example.invalid",
				...args,
			],
			{ cwd: temporary, encoding: "utf8" },
		);
		assert.equal(result.status, 0, result.stderr);
		return result.stdout.trim();
	};
	git("init", "-q");
	git("add", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "packages", "tools");
	git("commit", "-qm", "baseline");
	const base = git("rev-parse", "HEAD");
	const executables = join(temporary, "fixture-bin");
	const scanners = join(temporary, "node_modules/.cache/spec-security/bin");
	await mkdir(executables);
	await mkdir(scanners, { recursive: true });
	await writeFile(
		join(executables, "pnpm"),
		`#!${process.execPath}\nconst base = process.cwd().endsWith("/base"); console.log(base && process.env.INVALID_BASE_GRAPH ? "invalid JSON" : base ? process.env.BASE_GRAPH : process.env.CURRENT_GRAPH);\n`,
		{ mode: 0o755 },
	);
	await writeFile(
		join(scanners, "osv-scanner"),
		`#!${process.execPath}\nconst fs = require("node:fs"); fs.copyFileSync(process.argv.at(-1), process.env.SCANNED_BOM);\n`,
		{ mode: 0o755 },
	);
	const graph = (version) =>
		["core", "authority", "leaf", "oidc", "wallet", "crypto", "cli"].map((name) => ({
			name: `@oidfed/${name}`,
			...(name === "core"
				? { dependencies: { jose: { version }, zod: { version: "4.4.3" } } }
				: {}),
		}));
	const output = join(temporary, "scanned-bom.json");
	return {
		temporary,
		base,
		output,
		run(overrides = {}) {
			return spawnSync(process.execPath, ["scripts/security/run.mjs", "dependencies"], {
				cwd: temporary,
				env: {
					...process.env,
					PATH: `${executables}${delimiter}${process.env.PATH}`,
					SECURITY_BASE_SHA: base,
					CURRENT_GRAPH: JSON.stringify(graph("6.2.13")),
					BASE_GRAPH: JSON.stringify(graph("6.2.12")),
					SCANNED_BOM: output,
					...overrides,
				},
				encoding: "utf8",
			});
		},
	};
}

test("a baseline predating wallet scans the full current graph", async () => {
	const fixture = await dependencyFixture(false);
	try {
		const result = fixture.run();
		assert.equal(result.status, 0, result.stderr);
		assert.match(result.stdout, /baseline.*incomplete.*full current/i);
		const bom = JSON.parse(await readFile(fixture.output, "utf8"));
		assert.deepEqual(
			bom.components.map(({ name, version }) => `${name}@${version}`),
			["jose@6.2.13", "zod@4.4.3"],
		);
	} finally {
		await rm(fixture.temporary, { recursive: true, force: true });
	}
});

test("complete dependency baselines retain differential scanning", async () => {
	const fixture = await dependencyFixture(true);
	try {
		const result = fixture.run();
		assert.equal(result.status, 0, result.stderr);
		const bom = JSON.parse(await readFile(fixture.output, "utf8"));
		assert.deepEqual(
			bom.components.map(({ name, version }) => `${name}@${version}`),
			["jose@6.2.13"],
		);
	} finally {
		await rm(fixture.temporary, { recursive: true, force: true });
	}
});

test("invalid commits and corrupt or incomplete graphs fail without a scan", async () => {
	const fixture = await dependencyFixture(true);
	try {
		for (const overrides of [
			{ SECURITY_BASE_SHA: "0".repeat(40) },
			{ SECURITY_BASE_SHA: "invalid-ref" },
			{ INVALID_BASE_GRAPH: "1" },
			{ CURRENT_GRAPH: "[]" },
			{
				CURRENT_GRAPH: JSON.stringify(Array.from({ length: 5 }, () => ({ name: "@oidfed/core" }))),
			},
		]) {
			const result = fixture.run(overrides);
			assert.notEqual(result.status, 0);
			await assert.rejects(access(fixture.output));
		}
	} finally {
		await rm(fixture.temporary, { recursive: true, force: true });
	}
});

test("both workflow linters receive all workflow YAML files", async () => {
	const temporary = await scannerWorkspace();
	try {
		await mkdir(join(temporary, ".github/workflows"), { recursive: true });
		const files = ["ci.yml", "conformance.yml", "release.yml", "security.yml", "future.yaml"];
		for (const file of [...files, "notes.md"])
			await writeFile(join(temporary, ".github/workflows", file), "name: fixture\n");
		const bin = join(temporary, "node_modules/.cache/spec-security/bin");
		await mkdir(bin, { recursive: true });
		for (const tool of ["shellcheck", "actionlint", "zizmor"])
			await writeFile(
				join(bin, tool),
				`#!${process.execPath}\nconst fs = require("node:fs"); fs.appendFileSync(process.env.WORKFLOW_CALLS, JSON.stringify({tool: ${JSON.stringify(tool)}, args: process.argv.slice(2)}) + "\\n");`,
				{ mode: 0o755 },
			);
		const calls = join(temporary, "calls.txt");
		const result = spawnSync(process.execPath, ["scripts/security/run.mjs", "workflows"], {
			cwd: temporary,
			env: { ...process.env, WORKFLOW_CALLS: calls },
			encoding: "utf8",
		});
		assert.equal(result.status, 0, result.stderr);
		const actual = (await readFile(calls, "utf8"))
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line));
		assert.deepEqual(
			actual.map((call) => call.tool),
			["shellcheck", "actionlint", "zizmor"],
		);
		assert.deepEqual(actual[0].args, ["--version"]);
		assert.deepEqual(actual[1].args.slice(0, 2), ["-shellcheck", "shellcheck"]);
		for (const call of actual.slice(1))
			assert.deepEqual(
				call.args.filter((arg) => arg.startsWith(".github/")),
				files.map((file) => `.github/workflows/${file}`).sort(),
			);
		const workflow = await readFile(join(root, ".github/workflows/security.yml"), "utf8");
		for (const suffix of ["yml", "yaml"])
			assert.equal(
				workflow.split(`'.github/workflows/*.${suffix}'`).length - 1,
				2,
				"push and PR checks include workflow changes",
			);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

test("workflow checks fail before linting when ShellCheck is missing", async () => {
	const temporary = await scannerWorkspace();
	try {
		await mkdir(join(temporary, ".github/workflows"), { recursive: true });
		await writeFile(join(temporary, ".github/workflows/ci.yml"), "name: fixture\n");
		const result = spawnSync(process.execPath, ["scripts/security/run.mjs", "workflows"], {
			cwd: temporary,
			env: { ...process.env, PATH: join(temporary, "empty-bin") },
			encoding: "utf8",
		});
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /Required security tool 'shellcheck' was not found/);
		assert.match(result.stderr, /pnpm security:install/);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

test("workflow checks really inspect shell scripts with the installed ShellCheck", async () => {
	const temporary = await scannerWorkspace();
	try {
		const directory = join(temporary, ".github/workflows");
		await mkdir(directory, { recursive: true });
		const bin = join(temporary, "node_modules/.cache/spec-security/bin");
		await mkdir(bin, { recursive: true });
		for (const tool of ["shellcheck", "actionlint", "zizmor"])
			await symlink(join(root, "node_modules/.cache/spec-security/bin", tool), join(bin, tool));
		for (const [command, valid] of [
			['echo "$GITHUB_WORKSPACE"', true],
			["echo $GITHUB_WORKSPACE", false],
		]) {
			await writeFile(
				join(directory, "ci.yml"),
				`name: fixture\non: push\npermissions:\n  contents: read\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: bash\n        run: ${command}\n`,
			);
			const result = spawnSync(process.execPath, ["scripts/security/run.mjs", "workflows"], {
				cwd: temporary,
				encoding: "utf8",
			});
			if (valid) assert.equal(result.status, 0, result.stderr);
			else {
				assert.notEqual(result.status, 0);
				assert.match(result.stdout + result.stderr, /SC2086/);
			}
		}
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

test("queued concurrency is checked without hiding other workflow diagnostics", async () => {
	const temporary = await scannerWorkspace();
	try {
		const directory = join(temporary, ".github/workflows");
		await mkdir(directory, { recursive: true });
		const bin = join(temporary, "node_modules/.cache/spec-security/bin");
		await mkdir(bin, { recursive: true });
		for (const tool of ["shellcheck", "actionlint", "zizmor"])
			await symlink(join(root, "node_modules/.cache/spec-security/bin", tool), join(bin, tool));
		for (const [queue, cancel, extra, expected] of [
			["max", false, "", null],
			["unsupported", false, "", /Invalid queued concurrency/],
			["max", true, "", /Invalid queued concurrency/],
			["max", false, "      unexpected: value\n", /unexpected key "unexpected"/],
		]) {
			await writeFile(
				join(directory, "ci.yml"),
				`name: fixture\non: push\npermissions:\n  contents: read\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    concurrency:\n      group: fixture\n      queue: ${queue}\n      cancel-in-progress: ${cancel}\n${extra}    steps:\n      - run: echo safe\n`,
			);
			const result = spawnSync(process.execPath, ["scripts/security/run.mjs", "workflows"], {
				cwd: temporary,
				encoding: "utf8",
			});
			if (expected) {
				assert.notEqual(result.status, 0);
				assert.match(result.stdout + result.stderr, expected);
			} else assert.equal(result.status, 0, result.stderr);
		}
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});
