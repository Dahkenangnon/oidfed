#!/usr/bin/env node
/**
 * Pre-publish guard: ensure every publishable @oidfed/* package declares its
 * @oidfed/core reference via the pnpm workspace protocol, so `pnpm publish`
 * rewrites it to the current workspace core version. This prevents the bug
 * class where a hand-edited fixed version in dependencies/peerDependencies
 * causes published packages to drift apart and force two side-by-side copies
 * of @oidfed/core into consumer install trees.
 *
 * Exit codes:
 *   0  every check passes
 *   1  at least one violation found (details on stderr)
 *   2  invalid invocation / unreadable files
 *
 * Usage:
 *   node scripts/check-single-core.mjs
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const PUBLISHABLE = [
	"packages/core/package.json",
	"packages/authority/package.json",
	"packages/leaf/package.json",
	"packages/oidc/package.json",
	"tools/cli/package.json",
];

/**
 * Inspect a single package.json and report any rule violations.
 * Pure: takes a parsed package.json object plus the file path it came from,
 * returns an array of violation strings. Empty array == compliant.
 */
export function inspectPackage(pkg, displayPath) {
	const violations = [];
	const isCore = pkg.name === "@oidfed/core";

	const checkBucket = (bucketName) => {
		const bucket = pkg[bucketName];
		if (!bucket || typeof bucket !== "object") return;
		for (const [dep, spec] of Object.entries(bucket)) {
			if (dep !== "@oidfed/core") continue;
			if (isCore) {
				violations.push(
					`${displayPath}: ${pkg.name} declares a self-reference to @oidfed/core in ${bucketName}`,
				);
				continue;
			}
			if (typeof spec !== "string" || !spec.startsWith("workspace:")) {
				violations.push(
					`${displayPath}: ${pkg.name} declares @oidfed/core in ${bucketName} as "${spec}" — must use the workspace: protocol (e.g. "workspace:^") so pnpm rewrites it to the current core version on publish`,
				);
			}
		}
	};

	checkBucket("dependencies");
	checkBucket("peerDependencies");
	checkBucket("optionalDependencies");

	if (!isCore) {
		const inDeps = pkg.dependencies?.["@oidfed/core"];
		const inPeers = pkg.peerDependencies?.["@oidfed/core"];
		if (inDeps && inPeers) {
			violations.push(
				`${displayPath}: ${pkg.name} declares @oidfed/core in BOTH dependencies and peerDependencies — choose one`,
			);
		}
	}

	return violations;
}

/** Read & parse one package.json. Throws with a clear message on failure. */
function readPackage(relPath) {
	const abs = resolve(ROOT, relPath);
	if (!existsSync(abs)) {
		throw new Error(`Missing package.json: ${relPath}`);
	}
	try {
		return JSON.parse(readFileSync(abs, "utf8"));
	} catch (err) {
		throw new Error(`Cannot parse ${relPath}: ${err.message}`);
	}
}

function main() {
	const violations = [];
	for (const relPath of PUBLISHABLE) {
		let pkg;
		try {
			pkg = readPackage(relPath);
		} catch (err) {
			process.stderr.write(`${err.message}\n`);
			process.exit(2);
		}
		violations.push(...inspectPackage(pkg, relPath));
	}
	if (violations.length === 0) {
		process.stdout.write(
			"single-core check OK: all publishable packages use workspace: protocol for @oidfed/core\n",
		);
		process.exit(0);
	}
	process.stderr.write("single-core check FAILED:\n");
	for (const v of violations) {
		process.stderr.write(`  ✖ ${v}\n`);
	}
	process.exit(1);
}

const isEntry =
	import.meta.url === `file://${process.argv[1]}` ||
	import.meta.url.endsWith(process.argv[1] ?? "");
if (isEntry) main();
