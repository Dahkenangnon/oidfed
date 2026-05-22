#!/usr/bin/env node
/**
 * Extracts a release-notes body for a given scope + version from per-package
 * Keep-a-Changelog files and prints it to stdout. Used by the release workflow
 * to populate the GitHub Release body.
 *
 * Usage:
 *   node scripts/extract-changelog.mjs <scope> <version>
 *
 *   <scope>   core | authority | leaf | oidc | cli | all
 *   <version> e.g. 0.4.1
 *
 * Solo scope -> prints just that package's section (heading excluded).
 * 'all'      -> prints the root CHANGELOG section (if any), then one
 *               '### @oidfed/<name> <version>' block per package in the
 *               order core, authority, leaf, oidc, cli. Empty package
 *               sections render as '_(no user-facing changes)_'.
 *
 * Exit codes:
 *   0  success (stdout has the body)
 *   1  no matching section found for a solo scope
 *   2  invalid arguments / unknown scope
 */

import { existsSync, readFileSync } from "node:fs";

export const PKG_FILES = {
	core: "packages/core/CHANGELOG.md",
	authority: "packages/authority/CHANGELOG.md",
	leaf: "packages/leaf/CHANGELOG.md",
	oidc: "packages/oidc/CHANGELOG.md",
	cli: "tools/cli/CHANGELOG.md",
};

const EMPTY_PLACEHOLDER = "_(no user-facing changes)_";

function escapeRegExp(s) {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Read a CHANGELOG file and return the section body matching the given version.
 * Returns null if the file does not exist or no matching heading is found.
 * The H2 heading line itself is excluded from the returned body.
 */
export function extractSection(path, version) {
	if (!existsSync(path)) return null;
	const src = readFileSync(path, "utf8");
	return extractSectionFromText(src, version);
}

/** Same as `extractSection`, but operates on an in-memory string (used in tests). */
export function extractSectionFromText(src, version) {
	const lines = src.split("\n");
	const startRe = new RegExp(`^## \\[${escapeRegExp(version)}\\]`);
	const nextRe = /^## \[/;
	const start = lines.findIndex((l) => startRe.test(l));
	if (start === -1) return null;
	let end = lines.length;
	for (let i = start + 1; i < lines.length; i++) {
		if (nextRe.test(lines[i])) {
			end = i;
			break;
		}
	}
	return lines.slice(start + 1, end).join("\n").trim();
}

function renderSection(body) {
	return body && body.length > 0 ? body : EMPTY_PLACEHOLDER;
}

/**
 * Build the release-notes body. Pure function so it can be unit-tested without
 * touching the filesystem — pass an injected reader for the file lookups.
 */
export function buildBody(scope, version, readSection) {
	if (scope === "all") {
		const parts = [];
		const root = readSection("CHANGELOG.md");
		if (root) parts.push(root, "---");
		for (const name of Object.keys(PKG_FILES)) {
			const body = readSection(PKG_FILES[name]);
			parts.push(`### @oidfed/${name} ${version}\n\n${renderSection(body)}`);
		}
		return `${parts.join("\n\n")}\n`;
	}
	const path = PKG_FILES[scope];
	if (!path) return { error: `Unknown scope: ${scope}` };
	const body = readSection(path);
	if (!body) return { error: `No section [${version}] in ${path}` };
	return `${body}\n`;
}

function main() {
	const [, , scope, version] = process.argv;
	if (!scope || !version) {
		process.stderr.write(
			"Usage: extract-changelog.mjs <core|authority|leaf|oidc|cli|all> <version>\n",
		);
		process.exit(2);
	}
	const result = buildBody(scope, version, (p) => extractSection(p, version));
	if (typeof result === "object" && result.error) {
		process.stderr.write(`${result.error}\n`);
		process.exit(scope === "all" ? 2 : 1);
	}
	process.stdout.write(result);
}

// Run main() only when this file is the entry point (not when imported by tests).
const isEntry =
	import.meta.url === `file://${process.argv[1]}` ||
	import.meta.url.endsWith(process.argv[1] ?? "");
if (isEntry) main();
