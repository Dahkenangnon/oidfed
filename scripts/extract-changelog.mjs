#!/usr/bin/env node
/** Read a package's committed changelog section for its own GitHub Release. */

import { existsSync, readFileSync } from "node:fs";

import { fileURLToPath } from "node:url";
import { TARGETS, REPOSITORY } from "./release/catalog.mjs";

export const PKG_FILES = Object.fromEntries(TARGETS.map((p) => [p.scope, `${p.dir}/CHANGELOG.md`]));
const REMOTE = `https://github.com/${REPOSITORY}`;

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
	return lines
		.slice(start + 1, end)
		.join("\n")
		.trim();
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
	const path = PKG_FILES[scope];
	if (!Object.hasOwn(PKG_FILES, scope)) return { error: `Unknown scope: ${scope}` };
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
			"Usage: extract-changelog.mjs <core|authority|leaf|oidc|wallet|cli> <version> [prev-tag]\n",
		);
		process.exit(2);
	}
	const result = buildBody(scope, version, (p) => extractSection(p, version), prevTag || "");
	if (typeof result === "object" && result.error) {
		process.stderr.write(`${result.error}\n`);
		process.exit(1);
	}
	process.stdout.write(result);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
