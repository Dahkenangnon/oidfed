#!/usr/bin/env node
/**
 * Release helper — bumps version(s), regenerates per-package + root
 * CHANGELOGs from the git log, commits, tags, and pushes.
 *
 * Usage:
 *   node scripts/release.mjs <package> <bump>
 *
 * <package>  core | authority | leaf | oidc | cli | all
 * <bump>     patch | minor | major
 *
 * Examples:
 *   node scripts/release.mjs core patch
 *   node scripts/release.mjs all minor
 *
 * Or via pnpm:
 *   pnpm release core patch
 *   pnpm release all minor
 */

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const REMOTE = "https://github.com/Dahkenangnon/oidfed";

const PACKAGES = {
	core: { dir: "packages/core", scope: "core" },
	authority: { dir: "packages/authority", scope: "authority" },
	leaf: { dir: "packages/leaf", scope: "leaf" },
	oidc: { dir: "packages/oidc", scope: "oidc" },
	cli: { dir: "tools/cli", scope: "cli" },
};

// Conventional-commit types that surface in user-facing CHANGELOGs.
// Subjects with other types (chore, docs, ci, test, style, build, revert) are
// dropped — they still show in the GitHub commit-comparison view but don't
// belong in a Keep-a-Changelog file.
const TYPE_TO_HEADING = {
	feat: "### Features",
	fix: "### Bug Fixes",
	perf: "### Performance",
	refactor: "### Refactor",
};

const HEADING_ORDER = ["### Features", "### Bug Fixes", "### Performance", "### Refactor"];

const run = (cmd) => execSync(cmd, { stdio: "inherit" });

const readVersion = (dir) =>
	JSON.parse(readFileSync(resolve(dir, "package.json"), "utf8")).version;

/**
 * Returns the most recent annotated tag matching '<scope>/v*.*.*' that is an
 * ancestor of HEAD, or empty string if none exists.
 */
export function previousTagFor(scope) {
	try {
		return execSync(
			`git describe --tags --match '${scope}/v*.*.*' --abbrev=0 HEAD`,
			{ encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
		).trim();
	} catch {
		return "";
	}
}

/**
 * Parse a single conventional-commit subject. Returns null when the subject
 * doesn't match the conventional shape.
 */
export function parseSubject(subject) {
	const match = subject.match(
		/^(feat|fix|perf|refactor|test|docs|build|ci|chore|style|revert)(\([^)]+\))?(!?):\s+(.+)$/,
	);
	if (!match) return null;
	return {
		type: match[1],
		scope: match[2] ? match[2].slice(1, -1) : null,
		breaking: match[3] === "!",
		description: match[4],
	};
}

/**
 * Build the rendered CHANGELOG body (markdown) for the commits in
 * `<fromRef>..HEAD`. When `packagePath` is provided, the git log is path-
 * filtered to commits that touched files inside it. Returns empty string
 * when no qualifying commits exist.
 */
export function generateBody(fromRef, packagePath) {
	const range = fromRef ? `${fromRef}..HEAD` : "HEAD";
	const pathArg = packagePath ? `-- ${packagePath}` : "";
	const out = execSync(
		`git log --no-merges --pretty=format:'%H%x09%s' ${range} ${pathArg}`,
		{ encoding: "utf8" },
	)
		.split("\n")
		.filter((line) => line.length > 0);

	const grouped = {};
	for (const line of out) {
		const sep = line.indexOf("\t");
		if (sep < 0) continue;
		const sha = line.slice(0, sep);
		const subject = line.slice(sep + 1);
		const parsed = parseSubject(subject);
		if (parsed === null) continue;
		const heading = TYPE_TO_HEADING[parsed.type];
		if (!heading) continue;
		const bullet = `* ${parsed.description} ([${sha.slice(0, 7)}](${REMOTE}/commit/${sha}))`;
		(grouped[heading] ||= []).push(bullet);
	}

	const sections = [];
	for (const heading of HEADING_ORDER) {
		const lines = grouped[heading];
		if (!lines || lines.length === 0) continue;
		sections.push(`${heading}\n\n${lines.join("\n")}`);
	}
	return sections.join("\n\n");
}

/**
 * Replace `## [Unreleased]` with `## [Unreleased]\n\n## [<v>] - <date>\n\n<body>`.
 * When `body` is empty the section receives a stub placeholder so the
 * resulting file remains valid Keep-a-Changelog markdown.
 */
export function stampChangelog(changelogPath, v, fromRef, packagePath) {
	const src = readFileSync(changelogPath, "utf8");
	const marker = "## [Unreleased]";
	if (!src.includes(marker)) return;
	const date = new Date().toISOString().slice(0, 10);
	const body = generateBody(fromRef, packagePath);
	const block = body
		? `## [Unreleased]\n\n## [${v}] - ${date}\n\n${body}\n`
		: `## [Unreleased]\n\n## [${v}] - ${date}\n\n_No user-visible changes — released as part of the coordinated wave._\n`;
	writeFileSync(changelogPath, src.replace(marker, block));
}

// Top-level only runs when invoked as a script, not when imported by tests.
if (import.meta.url === `file://${process.argv[1]}`) {
	const [, , pkg, bump] = process.argv;
	const validPkgs = [...Object.keys(PACKAGES), "all"];
	const validBumps = ["patch", "minor", "major"];
	if (!validPkgs.includes(pkg) || !validBumps.includes(bump)) {
		console.error(
			`Usage: node scripts/release.mjs <${validPkgs.join("|")}> <${validBumps.join("|")}>`,
		);
		process.exit(1);
	}

	if (pkg === "all") {
		const prevAllTag = previousTagFor("all");
		for (const { dir } of Object.values(PACKAGES)) {
			run(`npm version ${bump} --no-git-tag-version --prefix ${dir}`);
		}
		run(`npm version ${bump} --no-git-tag-version`);

		const v = readVersion("packages/core");
		for (const { dir } of Object.values(PACKAGES)) {
			stampChangelog(`${dir}/CHANGELOG.md`, v, prevAllTag, dir);
		}
		stampChangelog("CHANGELOG.md", v, prevAllTag);

		const files = [
			...Object.values(PACKAGES).map(({ dir }) => `${dir}/package.json`),
			...Object.values(PACKAGES).map(({ dir }) => `${dir}/CHANGELOG.md`),
			"package.json",
			"CHANGELOG.md",
		].join(" ");

		run(`git add ${files}`);
		run(`git commit -m "chore(release): all v${v}"`);
		run(`git tag -a -m "release: all v${v}" all/v${v}`);
		run("git push");
		run(`git push origin all/v${v}`);
		console.log(`\nReleased all packages at v${v} → tag all/v${v}`);
	} else {
		const { dir, scope } = PACKAGES[pkg];
		const prevTag = previousTagFor(scope);

		run(`npm version ${bump} --no-git-tag-version --prefix ${dir}`);

		const v = readVersion(dir);
		const changelogPath = `${dir}/CHANGELOG.md`;
		stampChangelog(changelogPath, v, prevTag, dir);

		run(`git add ${dir}/package.json ${changelogPath}`);
		run(`git commit -m "chore(${scope}): release v${v}"`);
		run(`git tag -a -m "release: @oidfed/${scope} v${v}" ${scope}/v${v}`);
		run("git push");
		run(`git push origin ${scope}/v${v}`);
		console.log(`\nReleased @oidfed/${scope} at v${v} → tag ${scope}/v${v}`);
	}
}
