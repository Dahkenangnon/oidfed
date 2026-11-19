/** Packages whose published protocol implementation is covered by security checks. */

import { fileURLToPath } from "node:url";
import { resolve, relative, sep } from "node:path";
import { readdirSync } from "node:fs";

export const root = fileURLToPath(new URL("../../", import.meta.url));
export const packages = Object.freeze(["core", "authority", "leaf", "oidc", "wallet", "crypto"]);
export const sources = Object.freeze(packages.map((name) => `packages/${name}/src`));
export const selectors = Object.freeze(packages.flatMap((name) => ["--filter", `@oidfed/${name}`]));

/** Inspect every workflow, including newly added files, with both workflow linters. */
export function workflowFiles(cwd = root) {
	const files = readdirSync(resolve(cwd, ".github/workflows"), { withFileTypes: true })
		.filter((entry) => entry.isFile() && /\.ya?ml$/.test(entry.name))
		.map((entry) => `.github/workflows/${entry.name}`)
		.sort();
	if (files.length === 0) throw new Error("No workflows found to validate");
	return files;
}

/** Resolve a scanner target without accepting traversal outside the package allowlist. */
export function isPackageSource(path) {
	const local = relative(root, resolve(root, path)).split(sep).join("/");
	return sources.some((source) => local.startsWith(`${source}/`));
}
