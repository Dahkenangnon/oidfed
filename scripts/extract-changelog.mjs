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

const REMOTE = "https://github.com/Dahkenangnon/oidfed";
const EMPTY_PLACEHOLDER = "_(no user-facing changes)_";
const NO_CHANGE_RE = /no\s+user[\s-]?(?:visible|facing)/i;

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

function isEmptyBody(body) {
	return !body || body.length === 0 || NO_CHANGE_RE.test(body);
}

export function extractBreakingChanges(body) {
	if (!body) return null;
	const lines = body.split("\n");
	const breaking = lines.filter((l) => l.includes("**BREAKING"));
	return breaking.length > 0 ? breaking.join("\n") : null;
}

/**
 * Build the release-notes body. Pure function so it can be unit-tested without
 * touching the filesystem — pass an injected reader for the file lookups.
 */
export function buildBody(scope, version, readSection, prevTag) {
	if (scope === "all") {
		const parts = [];
		const root = readSection("CHANGELOG.md");

		const rootBreaking = root ? extractBreakingChanges(root) : null;
		if (rootBreaking) parts.push(`### ⚠ BREAKING\n\n${rootBreaking}`, "---");

		if (root) parts.push(root, "---");

		const pkgBodies = {};
		for (const name of Object.keys(PKG_FILES)) {
			pkgBodies[name] = readSection(PKG_FILES[name]);
		}

		const unchanged = Object.entries(pkgBodies)
			.filter(([, b]) => isEmptyBody(b))
			.map(([n]) => n);
		const changed = Object.fromEntries(
			Object.entries(pkgBodies).filter(([n]) => !unchanged.includes(n)),
		);

		if (unchanged.length === Object.keys(PKG_FILES).length) {
			parts.push(
				"All packages released as a coordinated wave with no user-visible changes.",
			);
		} else if (new Set(Object.values(changed)).size <= 1) {
			const [sharedBody] = Object.values(changed);
			const changedList = Object.keys(changed);
			if (changedList.length > 1) {
				parts.push(
					`All packages received the same update:\n\n${sharedBody}`,
				);
			} else {
				parts.push(
					`### @oidfed/${changedList[0]} ${version}\n\n${sharedBody}`,
				);
			}
			if (unchanged.length > 0) {
				const names = unchanged
					.map((n) => `@oidfed/${n}`)
					.join(", ");
				parts.push(`_${names} — no user-visible changes._`);
			}
		} else {
			for (const [name, body] of Object.entries(pkgBodies)) {
				parts.push(
					`### @oidfed/${name} ${version}\n\n${renderSection(body)}`,
				);
			}
		}

		if (prevTag) {
			parts.push(
				`\n---\n**Full Changelog**: ${REMOTE}/compare/${prevTag}...all/v${version}`,
			);
		}

		return `${parts.join("\n\n")}\n`;
	}

	const path = PKG_FILES[scope];
	if (!path) return { error: `Unknown scope: ${scope}` };
	const body = readSection(path);
	if (!body) return { error: `No section [${version}] in ${path}` };

	const soloBreaking = extractBreakingChanges(body);
	let result = "";
	if (soloBreaking) result += `### ⚠ BREAKING\n\n${soloBreaking}\n\n`;
	result += `${body}\n`;

	if (prevTag) {
		result += `\n---\n**Full Changelog**: ${REMOTE}/compare/${prevTag}...${scope}/v${version}\n`;
	}

	return result;
}

function main() {
	const [, , scope, version, prevTag] = process.argv;
	if (!scope || !version) {
		process.stderr.write(
			"Usage: extract-changelog.mjs <core|authority|leaf|oidc|cli|all> <version> [prev-tag]\n",
		);
		process.exit(2);
	}
	const result = buildBody(
		scope,
		version,
		(p) => extractSection(p, version),
		prevTag || "",
	);
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
