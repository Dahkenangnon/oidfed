#!/usr/bin/env node
/**
 * Release helper — bumps version(s), commits, tags, and pushes.
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

const PACKAGES = {
	core: { dir: "packages/core", scope: "core" },
	authority: { dir: "packages/authority", scope: "authority" },
	leaf: { dir: "packages/leaf", scope: "leaf" },
	oidc: { dir: "packages/oidc", scope: "oidc" },
	cli: { dir: "tools/cli", scope: "cli" },
};

const [, , pkg, bump] = process.argv;

const validPkgs = [...Object.keys(PACKAGES), "all"];
const validBumps = ["patch", "minor", "major"];

if (!validPkgs.includes(pkg) || !validBumps.includes(bump)) {
	console.error(
		`Usage: node scripts/release.mjs <${validPkgs.join("|")}> <${validBumps.join("|")}>`,
	);
	process.exit(1);
}

const run = (cmd) => execSync(cmd, { stdio: "inherit" });
const version = (dir) =>
	JSON.parse(readFileSync(resolve(dir, "package.json"), "utf8")).version;

/**
 * Renames `## [Unreleased]` → `## [<v>] - <YYYY-MM-DD>` in the given
 * CHANGELOG.md and inserts a fresh empty `## [Unreleased]` above it.
 * No-ops silently if the marker is absent.
 */
function stampChangelog(changelogPath, v) {
	const src = readFileSync(changelogPath, "utf8");
	const marker = "## [Unreleased]";
	if (!src.includes(marker)) return;
	const today = new Date().toISOString().slice(0, 10);
	const updated = src.replace(
		marker,
		`## [Unreleased]\n\n## [${v}] - ${today}`,
	);
	writeFileSync(changelogPath, updated);
}

if (pkg === "all") {
	// Bump all packages + root
	for (const { dir } of Object.values(PACKAGES)) {
		run(`npm version ${bump} --no-git-tag-version --prefix ${dir}`);
	}
	run(`npm version ${bump} --no-git-tag-version`);

	const v = version("packages/core");
	// Stamp every per-package changelog + root
	for (const { dir } of Object.values(PACKAGES)) {
		stampChangelog(`${dir}/CHANGELOG.md`, v);
	}
	stampChangelog("CHANGELOG.md", v);
	const files = [
		...Object.values(PACKAGES).map(({ dir }) => `${dir}/package.json`),
		...Object.values(PACKAGES).map(({ dir }) => `${dir}/CHANGELOG.md`),
		"package.json",
		"CHANGELOG.md",
	].join(" ");

	run(`git add ${files}`);
	run(`git commit -m "chore: release all v${v} [skip ci]"`);
	run(`git tag all/v${v}`);
	run("git push");
	run(`git push origin all/v${v}`);
	console.log(`\nReleased all packages at v${v} → tag all/v${v}`);
} else {
	const { dir, scope } = PACKAGES[pkg];
	run(`npm version ${bump} --no-git-tag-version --prefix ${dir}`);

	const v = version(dir);
	const changelogPath = `${dir}/CHANGELOG.md`;
	stampChangelog(changelogPath, v);
	run(`git add ${dir}/package.json ${changelogPath}`);
	run(`git commit -m "chore(${scope}): release v${v} [skip ci]"`);
	run(`git tag ${scope}/v${v}`);
	run("git push");
	run(`git push origin ${scope}/v${v}`);
	console.log(`\nReleased @oidfed/${scope} at v${v} → tag ${scope}/v${v}`);
}
