/** Translate pnpm's resolved production graph into a scoped OSV input. */

import { execFileSync } from "node:child_process";
import { TARGETS } from "../release/catalog.mjs";
import { root } from "./scope.mjs";

const packageNames = new Set(TARGETS.map(({ name }) => name));
const selectors = TARGETS.flatMap(({ name }) => ["--filter", name]);

/** Only compare complete historical inputs; an absent package requires a full current scan. */
export function baselineFiles(base, cwd = root) {
	if (!/^[0-9a-f]{40}$/.test(base))
		throw new Error("SECURITY_BASE_SHA must be a full commit identifier");
	execFileSync("git", ["cat-file", "-e", `${base}^{commit}`], {
		cwd,
		stdio: ["ignore", "pipe", "pipe"],
	});
	const required = [
		"package.json",
		"pnpm-lock.yaml",
		"pnpm-workspace.yaml",
		...TARGETS.map(({ dir }) => `${dir}/package.json`),
	];
	const paths = new Set(
		execFileSync("git", ["ls-tree", "-r", "--name-only", "-z", base, "--", ...required], {
			cwd,
			encoding: "utf8",
		}).split("\0"),
	);
	return required.every((path) => paths.has(path)) ? required : undefined;
}

/** Preserve exact resolved versions; workspace nodes are traversed but are not registry packages. */
export function registryPackages(projects) {
	const found = new Map();
	const seen = new WeakSet();
	function visit(dependencies = {}) {
		for (const [name, node] of Object.entries(dependencies)) {
			if (!node || typeof node !== "object" || seen.has(node)) continue;
			seen.add(node);
			if (typeof node.version === "string" && !/^(link:|workspace:|file:)/.test(node.version)) {
				// pnpm keeps peer bindings in graph paths, rather than the package's own version.
				const version = node.version.replace(/\(.*/, "");
				if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version))
					throw new Error(`Unexpected resolved version for ${name}`);
				found.set(`${name}@${version}`, { name, version, ecosystem: "npm" });
			}
			visit(node.dependencies);
			visit(node.optionalDependencies);
		}
	}
	for (const project of projects) {
		if (!packageNames.has(project.name))
			throw new Error("Production graph includes an out-of-scope workspace");
		visit(project.dependencies);
		visit(project.optionalDependencies);
	}
	return [...found.values()].sort((a, b) =>
		`${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`),
	);
}

export function productionGraph(cwd = root) {
	// pnpm 10 accepts this documented list option through its config namespace.
	const json = execFileSync(
		"pnpm",
		[
			"--config.lockfile-only=true",
			"list",
			"--prod",
			"--depth",
			"Infinity",
			"--json",
			...selectors,
		],
		{ cwd, encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
	);
	const projects = JSON.parse(json);
	if (
		!Array.isArray(projects) ||
		projects.length !== packageNames.size ||
		new Set(projects.map((project) => project.name)).size !== packageNames.size ||
		projects.some((project) => !packageNames.has(project.name))
	)
		throw new Error("Incomplete published-package dependency graph");
	return registryPackages(projects);
}

export function cycloneDxInput(dependencies) {
	if (dependencies.length === 0) throw new Error("Refusing an empty dependency scan");
	return {
		bomFormat: "CycloneDX",
		specVersion: "1.5",
		version: 1,
		components: dependencies.map(({ name, version }) => ({
			type: "library",
			name,
			version,
			purl: `pkg:npm/${name.replace(/^@/, "%40")}@${version}`,
		})),
	};
}
