/** Run package-scoped checks, keeping generated scanner inputs and artifacts temporary. */

import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, mkdir, readdir, rm, symlink } from "node:fs/promises";
import { join, delimiter } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import ts from "typescript";
import { parse as parseYaml } from "yaml";
import { packages, sources, root, workflowFiles } from "./scope.mjs";
import { bin, tools } from "./install.mjs";
import { productionGraph, cycloneDxInput, baselineFiles } from "./dependency-graph.mjs";
import { knownCycles } from "./known-cycles.mjs";

const environment = {
	...process.env,
	PATH: [bin, process.env.PATH].filter(Boolean).join(delimiter),
};

function run(command, args, options = {}) {
	const result = spawnSync(command, args, {
		cwd: root,
		env: environment,
		stdio: "inherit",
		...options,
	});
	if (result.error) {
		if (result.error.code === "ENOENT") {
			const setup = Object.hasOwn(tools, command)
				? "pnpm security:install"
				: "pnpm install --frozen-lockfile";
			throw new Error(`Required security tool '${command}' was not found. Run ${setup}.`, {
				cause: result.error,
			});
		}
		throw result.error;
	}
	if (result.status !== 0) throw new Error(`${command} failed (${result.status ?? result.signal})`);
	return result.stdout;
}
function pnpm(...args) {
	return run("pnpm", ["exec", ...args]);
}

/** Compare a directed cycle independently of which node the scanner reports first. */
export function cycleKey(paths) {
	return paths
		.map((_, index) => [...paths.slice(index), ...paths.slice(0, index)].join(" -> "))
		.sort()[0];
}

async function architecture() {
	const result = spawnSync(
		join(root, "node_modules/.bin/depcruise"),
		["-c", "scripts/security/dependencies.config.mjs", "-T", "json", ...sources],
		{ cwd: root, env: environment, encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
	);
	if (result.error) {
		if (result.error.code === "ENOENT")
			throw new Error("Dependency analyzer was not found. Run pnpm install --frozen-lockfile.", {
				cause: result.error,
			});
		throw result.error;
	}
	if (![0, 1].includes(result.status))
		throw new Error(`Dependency analysis did not complete: ${result.stderr.trim()}`);
	let report;
	try {
		report = JSON.parse(result.stdout);
	} catch (cause) {
		throw new Error(
			"Dependency analyzer did not return valid JSON; no architecture assessment was made.",
			{ cause },
		);
	}
	const known = new Set(
		knownCycles.map((cycle) => cycleKey(cycle.map((path) => `packages/core/src/${path}`))),
	);
	const violations = report.summary.violations.filter(
		(violation) =>
			violation.type !== "cycle" || !known.has(cycleKey(violation.cycle.map((part) => part.name))),
	);
	if (violations.length) throw new Error(JSON.stringify(violations, null, 2));
	console.log(
		`Architecture: ${report.modules.length} modules; existing runtime cycles recognized, no new violations`,
	);
}

async function dependencies(temporary) {
	let graph = productionGraph();
	const base = process.env.SECURITY_BASE_SHA;
	if (base) {
		const files = baselineFiles(base);
		if (!files) {
			console.log("Dependency baseline is incomplete; scanning the full current production graph");
		} else {
			const baseRoot = join(temporary, "base");
			await mkdir(baseRoot);
			const archive = join(temporary, "base.tar");
			run("git", ["archive", "--format=tar", `--output=${archive}`, base, ...files]);
			run("tar", ["xf", archive, "-C", baseRoot]);
			const previous = new Set(
				productionGraph(baseRoot).map((entry) => `${entry.name}@${entry.version}`),
			);
			graph = graph.filter((entry) => !previous.has(`${entry.name}@${entry.version}`));
			if (graph.length === 0) {
				console.log("No changed production dependencies in the five packages");
				return;
			}
		}
	}
	const bom = cycloneDxInput(graph);
	const path = join(temporary, "bom.json");
	await writeFile(path, JSON.stringify(bom));
	console.log(`Checking ${graph.length} exact production dependency versions`);
	// Only the temporary BOM is an input. Never scan the monorepo lockfile directly.
	run("osv-scanner", ["scan", "source", "--no-resolve", "--sbom", path]);
}

async function artifacts(temporary) {
	const savedDirectory = process.env.RELEASE_ARTIFACT_DIR;
	const saved = savedDirectory
		? (await import("../release/artifacts.mjs")).loadArtifacts(savedDirectory)
		: undefined;
	const consumer = join(temporary, "consumer");
	await mkdir(join(consumer, "node_modules/@oidfed"), { recursive: true });
	await writeFile(join(consumer, "package.json"), '{"private":true,"type":"module"}');
	for (const name of packages) {
		const directory = join(temporary, name);
		await mkdir(directory);
		let path;
		if (saved)
			path = join(savedDirectory, saved.packages.find((record) => record.scope === name).file);
		else {
			run("pnpm", ["--filter", `@oidfed/${name}`, "pack", "--pack-destination", directory]);
			const tarball = (await readdir(directory)).find((file) => file.endsWith(".tgz"));
			if (!tarball) throw new Error(`No packed artifact for ${name}`);
			path = join(directory, tarball);
		}
		pnpm("publint", path, "--strict");
		pnpm("attw", path);
		const packageDirectory = join(consumer, `node_modules/@oidfed/${name}`);
		await mkdir(packageDirectory);
		run("tar", ["xzf", path, "--strip-components=1", "-C", packageDirectory]);
		// Scan outside node_modules: secret scanners intentionally skip dependency directories.
		run("tar", ["xzf", path, "-C", directory]);
		run("gitleaks", [
			"dir",
			join(directory, "package"),
			"--redact=100",
			"--no-banner",
			"--config",
			"scripts/security/gitleaks.toml",
		]);
	}
	// External runtime declarations are the exact installed versions of the core dependencies.
	for (const name of ["jose", "zod"]) {
		const require = createRequire(join(root, "packages/core/package.json"));
		const packagePath = require.resolve(name);
		let directory = packagePath;
		while (true) {
			directory = join(directory, "..");
			try {
				if (JSON.parse(await readFile(join(directory, "package.json"), "utf8")).name === name)
					break;
			} catch {
				/* Find the dependency root from its public entrypoint. */
			}
			if (directory === "/") throw new Error(`Cannot locate dependency ${name}`);
		}
		await symlink(directory, join(consumer, `node_modules/${name}`), "dir");
	}
	const sample =
		'import { entityId, type FederationOptions } from "@oidfed/core";\nimport { Leaf } from "@oidfed/leaf";\nimport { TrustAnchor } from "@oidfed/authority";\nimport { OidcProviderRole } from "@oidfed/oidc";\nimport { WalletProviderRole } from "@oidfed/wallet";\nconst options: FederationOptions = {maxTotalFetches:0};\nvoid [options, entityId("https://entity.example"), Leaf, TrustAnchor, OidcProviderRole, WalletProviderRole];\n';
	for (const [extension, module, moduleResolution] of [
		["mts", ts.ModuleKind.NodeNext, ts.ModuleResolutionKind.NodeNext],
		["cts", ts.ModuleKind.NodeNext, ts.ModuleResolutionKind.NodeNext],
		["ts", ts.ModuleKind.ESNext, ts.ModuleResolutionKind.Bundler],
	]) {
		const file = join(consumer, `consumer.${extension}`);
		await writeFile(file, sample);
		const program = ts.createProgram([file], {
			strict: true,
			noEmit: true,
			target: ts.ScriptTarget.ES2022,
			module,
			moduleResolution,
			skipLibCheck: false,
		});
		const diagnostics = ts.getPreEmitDiagnostics(program);
		if (diagnostics.length)
			throw new Error(
				ts.formatDiagnosticsWithColorAndContext(diagnostics, {
					getCanonicalFileName: (file) => file,
					getCurrentDirectory: () => consumer,
					getNewLine: () => "\n",
				}),
			);
	}
	// Exercise both exports branches from the packed consumer, without workspace path mappings.
	run(
		process.execPath,
		[
			"--input-type=module",
			"-e",
			'import {createRequire} from "node:module"; const require=createRequire(import.meta.url); for(const name of ["core","authority","leaf","oidc","wallet"]){if(!Object.keys(await import("@oidfed/"+name)).length || !Object.keys(require("@oidfed/"+name)).length)throw Error(name);}',
		],
		{ cwd: consumer },
	);
	// Resolve every public-contract import from the packed consumer, not workspace symlinks.
	await symlink(join(root, "node_modules/tsd"), join(consumer, "node_modules/tsd"), "dir");
	const contracts = join(consumer, "public-api.test-d.ts");
	await writeFile(contracts, await readFile(join(root, "tests/security/public-api.test-d.ts")));
	run(
		join(root, "node_modules/.bin/tsd"),
		["--typings", "node_modules/@oidfed/core/dist/index.d.ts", "--files", "public-api.test-d.ts"],
		{ cwd: consumer },
	);
}

async function fuzz(temporary) {
	const target = join(temporary, "fuzz.mjs");
	await build({
		entryPoints: ["tests/security/fuzz.ts"],
		outfile: target,
		bundle: true,
		format: "esm",
		platform: "node",
		packages: "external",
		sourcemap: "inline",
	});
	// Keep dependency resolution local while storing corpora and findings outside the repository.
	await symlink(join(root, "packages/core/node_modules"), join(temporary, "node_modules"), "dir");
	const corpus = join(temporary, "corpus");
	await mkdir(corpus);
	const seeds = [
		"{}",
		'{"metadata_policy":{"__proto__":{"constructor":{"value":"canary"}}}}',
		'{"metadata_policy":{"x":{"a":{"value":1,"value":2}}}}',
		'{"extension":' + "[".repeat(12000) + "0" + "]".repeat(12000) + "}",
		"entity_type=a&entity_type=b&__proto__=x",
	];
	for (const [index, seed] of seeds.entries()) await writeFile(join(corpus, `seed-${index}`), seed);
	const seconds = process.env.FUZZ_SECONDS ?? "20";
	if (!/^\d+$/.test(seconds) || Number(seconds) < 1 || Number(seconds) > 300)
		throw new Error("FUZZ_SECONDS must be between 1 and 300");
	pnpm(
		"jazzer",
		target,
		corpus,
		"--includes",
		target,
		"--",
		`-max_total_time=${seconds}`,
		"-max_len=65536",
		`-artifact_prefix=${temporary}/`,
	);
}

async function main(command) {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-security-"));
	let complete = false;
	try {
		switch (command) {
			case "lint":
				await (await import("./lint.mjs")).lintSources();
				break;
			case "architecture":
				await architecture();
				break;
			case "advisory":
				pnpm(
					"knip",
					"--config",
					"scripts/security/knip.config.mjs",
					...packages.flatMap((name) => ["-W", `packages/${name}`]),
					"--no-progress",
					"--no-exit-code",
				);
				pnpm(
					"jscpd",
					...sources,
					"--format",
					"typescript",
					"--reporters",
					"console",
					"--threshold",
					"100",
					"--min-lines",
					"15",
				);
				break;
			case "secrets":
				for (const name of packages)
					run("gitleaks", [
						"dir",
						`packages/${name}`,
						"--redact=100",
						"--no-banner",
						"--config",
						"scripts/security/gitleaks.toml",
					]);
				break;
			case "dependencies":
				await dependencies(temporary);
				break;
			case "artifacts":
				await artifacts(temporary);
				break;
			case "fuzz":
				await fuzz(temporary);
				break;
			case "mutation":
				pnpm("stryker", "run", "scripts/security/stryker.config.mjs");
				break;
			case "workflows": {
				const workflows = workflowFiles();
				let queuedConcurrency = false;
				for (const file of workflows) {
					const document = parseYaml(await readFile(join(root, file), "utf8"));
					for (const concurrency of [
						document?.concurrency,
						...Object.values(document?.jobs ?? {}).map((job) => job.concurrency),
					]) {
						if (concurrency && Object.hasOwn(concurrency, "queue")) {
							if (
								!["single", "max"].includes(concurrency.queue) ||
								(concurrency.queue === "max" && concurrency["cancel-in-progress"] !== false)
							)
								throw new Error(`Invalid queued concurrency in ${file}`);
							queuedConcurrency = true;
						}
					}
				}
				// actionlint silently skips shell analysis unless ShellCheck is available.
				run("shellcheck", ["--version"]);
				// GitHub supports queue, but actionlint 1.7.12 predates it. Validate it above;
				// retain every other syntax and security diagnostic from the pinned linter.
				run("actionlint", [
					"-shellcheck",
					"shellcheck",
					...(queuedConcurrency
						? ["-ignore", '^unexpected key "queue" for "concurrency" section\\.']
						: []),
					...workflows,
				]);
				run("zizmor", ["--offline", "--min-severity", "low", ...workflows]);
				break;
			}
			default:
				throw new Error(
					"Choose lint, architecture, advisory, secrets, dependencies, artifacts, fuzz, mutation, or workflows",
				);
		}
		complete = true;
	} finally {
		if (complete) await rm(temporary, { recursive: true, force: true });
		else
			console.error(
				`Check did not complete successfully; temporary evidence retained at ${temporary}`,
			);
	}
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main(process.argv[2]);
