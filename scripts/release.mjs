#!/usr/bin/env node
/**
 * Release helper — bumps version(s), regenerates per-package + root
 * CHANGELOGs from the git log, commits, tags, and pushes.
 *
 * Usage:
 *   node scripts/release.mjs <package> <bump> [--dry-run|--prepare]
 *   node scripts/release.mjs <package> --finalize
 *
 * <package>  core | authority | leaf | oidc | cli | all
 * <bump>     patch | minor | major
 *
 * Examples:
 *   node scripts/release.mjs core patch --prepare
 *   node scripts/release.mjs core --finalize
 *   node scripts/release.mjs all minor --dry-run
 *
 * Or via pnpm:
 *   pnpm release core patch --prepare
 *   pnpm release core --finalize
 *   pnpm release all minor --dry-run
 */

import { execFileSync, execSync } from "node:child_process";
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

function readText(path, readFile = readFileSync) {
	return readFile(resolve(path), "utf8");
}

function updateJsonVersion(src, version) {
	const json = JSON.parse(src);
	json.version = version;
	return `${JSON.stringify(json, null, "\t")}\n`;
}

export function bumpVersion(version, bump) {
	const match = version.match(/^(\d+)\.(\d+)\.(\d+)(-.+)?$/);
	if (!match) throw new Error(`Unsupported version format: ${version}`);
	const major = Number(match[1]);
	const minor = Number(match[2]);
	const patch = Number(match[3]);
	if (bump === "major") return `${major + 1}.0.0`;
	if (bump === "minor") return `${major}.${minor + 1}.0`;
	if (bump === "patch") return `${major}.${minor}.${patch + 1}`;
	throw new Error(`Unsupported bump: ${bump}`);
}

/**
 * Returns the most recent annotated tag matching '<scope>/v*.*.*' that is an
 * ancestor of HEAD, or empty string if none exists.
 */
export function previousTagFor(scope) {
	try {
		return execFileSync(
			"git",
			["describe", "--tags", "--match", `${scope}/v*.*.*`, "--abbrev=0", "HEAD"],
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
	const args = ["log", "--no-merges", "--pretty=format:%H%x09%s", range];
	if (packagePath) args.push("--", packagePath);
	const out = execFileSync(
		"git",
		args,
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
 * When `skipBody` is true, the body is left empty for manual curation.
 */
export function stampChangelogText(src, v, body, date, skipBody = false) {
	const marker = "## [Unreleased]";
	if (!src.includes(marker)) return src;
	const renderedBody = skipBody ? "" : body;
	let block;
	if (renderedBody) {
		block = `## [Unreleased]\n\n## [${v}] - ${date}\n\n${renderedBody}\n`;
	} else if (skipBody) {
		block = `## [Unreleased]\n\n## [${v}] - ${date}\n\n`;
	} else {
		block = `## [Unreleased]\n\n## [${v}] - ${date}\n\n_No user-visible changes — released as part of the coordinated wave._\n`;
	}
	return src.replace(marker, block);
}

export function stampChangelog(changelogPath, v, fromRef, packagePath, skipBody = false) {
	const src = readFileSync(changelogPath, "utf8");
	const date = new Date().toISOString().slice(0, 10);
	const body = skipBody ? "" : generateBody(fromRef, packagePath);
	writeFileSync(changelogPath, stampChangelogText(src, v, body, date, skipBody));
}

function packageTargets(pkg) {
	if (pkg === "all") return Object.values(PACKAGES);
	return [PACKAGES[pkg]];
}

function changedFile(path, before, after) {
	return before === after ? null : { path, before, after };
}

function packageJsonPath(target) {
	return `${target.dir}/package.json`;
}

function packageChangelogPath(target) {
	return `${target.dir}/CHANGELOG.md`;
}

function targetFiles(pkg) {
	const files = [];
	for (const target of packageTargets(pkg)) {
		files.push(packageJsonPath(target), packageChangelogPath(target));
	}
	if (pkg === "all") files.push("package.json", "CHANGELOG.md");
	return files;
}

function hasChangelogSection(src, version) {
	const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	return new RegExp(`^## \\[${escaped}\\]`, "m").test(src);
}

export function createReleasePlan(pkg, bump, options = {}) {
	const readFile = options.readFile ?? readFileSync;
	const previousTag = options.previousTagFor ?? previousTagFor;
	const bodyGenerator = options.generateBody ?? generateBody;
	const date =
		options.date ?? (options.now ? options.now().toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10));

	const files = [];
	const targets = packageTargets(pkg);
	const scope = pkg === "all" ? "all" : PACKAGES[pkg].scope;
	const prevTag = previousTag(scope);
	let version;

	for (const target of targets) {
		const packagePath = packageJsonPath(target);
		const packageBefore = readText(packagePath, readFile);
		const nextVersion = bumpVersion(JSON.parse(packageBefore).version, bump);
		version ??= nextVersion;
		const packageAfter = updateJsonVersion(packageBefore, nextVersion);
		const packageChange = changedFile(packagePath, packageBefore, packageAfter);
		if (packageChange) files.push(packageChange);

		const changelogPath = packageChangelogPath(target);
		const changelogBefore = readText(changelogPath, readFile);
		const changelogAfter = stampChangelogText(
			changelogBefore,
			nextVersion,
			bodyGenerator(prevTag, target.dir),
			date,
		);
		const changelogChange = changedFile(changelogPath, changelogBefore, changelogAfter);
		if (changelogChange) files.push(changelogChange);
	}

	if (pkg === "all") {
		const rootPackagePath = "package.json";
		const rootPackageBefore = readText(rootPackagePath, readFile);
		const rootVersion = bumpVersion(JSON.parse(rootPackageBefore).version, bump);
		const rootPackageAfter = updateJsonVersion(rootPackageBefore, rootVersion);
		const rootPackageChange = changedFile(rootPackagePath, rootPackageBefore, rootPackageAfter);
		if (rootPackageChange) files.push(rootPackageChange);

		const rootChangelogPath = "CHANGELOG.md";
		const rootChangelogBefore = readText(rootChangelogPath, readFile);
		const rootChangelogAfter = stampChangelogText(rootChangelogBefore, version, "", date, true);
		const rootChangelogChange = changedFile(rootChangelogPath, rootChangelogBefore, rootChangelogAfter);
		if (rootChangelogChange) files.push(rootChangelogChange);
	}

	const gitAddPaths = files.map((file) => file.path);
	const tagName = `${scope}/v${version}`;
	const commitMessage =
		scope === "all" ? `chore(release): all v${version}` : `chore(${scope}): release v${version}`;
	const tagMessage =
		scope === "all" ? `release: all v${version}` : `release: @oidfed/${scope} v${version}`;
	const pushCommands = ["git push", `git push origin ${tagName}`];

	return {
		scope,
		version,
		files,
		gitAddPaths,
		commitMessage,
		tagName,
		tagMessage,
		pushCommands,
	};
}

export function createFinalizePlan(pkg, options = {}) {
	const readFile = options.readFile ?? readFileSync;
	const scope = pkg === "all" ? "all" : PACKAGES[pkg].scope;
	const targets = packageTargets(pkg);
	const versionSourcePath = packageJsonPath(targets[0]);
	const version = JSON.parse(readText(versionSourcePath, readFile)).version;
	const expectedPaths = targetFiles(pkg);

	for (const target of targets) {
		const path = packageJsonPath(target);
		const targetVersion = JSON.parse(readText(path, readFile)).version;
		if (targetVersion !== version) {
			throw new Error(
				`Prepared release version mismatch: ${path} has ${targetVersion}, expected ${version}`,
			);
		}
		const changelogPath = packageChangelogPath(target);
		if (!hasChangelogSection(readText(changelogPath, readFile), version)) {
			throw new Error(`Prepared release is missing ## [${version}] in ${changelogPath}`);
		}
	}

	if (pkg === "all") {
		const rootVersion = JSON.parse(readText("package.json", readFile)).version;
		if (rootVersion !== version) {
			throw new Error(
				`Prepared release version mismatch: package.json has ${rootVersion}, expected ${version}`,
			);
		}
		if (!hasChangelogSection(readText("CHANGELOG.md", readFile), version)) {
			throw new Error(`Prepared release is missing ## [${version}] in CHANGELOG.md`);
		}
	}

	return {
		scope,
		version,
		gitAddPaths: expectedPaths,
		commitMessage:
			scope === "all" ? `chore(release): all v${version}` : `chore(${scope}): release v${version}`,
		tagName: `${scope}/v${version}`,
		tagMessage:
			scope === "all" ? `release: all v${version}` : `release: @oidfed/${scope} v${version}`,
		pushCommands: ["git push", `git push origin ${scope}/v${version}`],
		expectedPaths,
	};
}

function splitLines(text) {
	const lines = text.split("\n");
	if (lines.at(-1) === "") lines.pop();
	return lines;
}

export function unifiedDiff(path, before, after) {
	if (before === after) return "";
	const oldLines = splitLines(before);
	const newLines = splitLines(after);
	let prefix = 0;
	while (
		prefix < oldLines.length &&
		prefix < newLines.length &&
		oldLines[prefix] === newLines[prefix]
	) {
		prefix++;
	}
	let suffix = 0;
	while (
		suffix < oldLines.length - prefix &&
		suffix < newLines.length - prefix &&
		oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
	) {
		suffix++;
	}

	const context = 3;
	const oldStart = Math.max(0, prefix - context);
	const newStart = Math.max(0, prefix - context);
	const oldChangedEnd = oldLines.length - suffix;
	const newChangedEnd = newLines.length - suffix;
	const oldEnd = Math.min(oldLines.length, oldChangedEnd + context);
	const newEnd = Math.min(newLines.length, newChangedEnd + context);
	const hunk = [
		`diff --git a/${path} b/${path}`,
		`--- a/${path}`,
		`+++ b/${path}`,
		`@@ -${oldStart + 1},${oldEnd - oldStart} +${newStart + 1},${newEnd - newStart} @@`,
	];

	for (let i = oldStart; i < prefix; i++) hunk.push(` ${oldLines[i]}`);
	for (let i = prefix; i < oldChangedEnd; i++) hunk.push(`-${oldLines[i]}`);
	for (let i = prefix; i < newChangedEnd; i++) hunk.push(`+${newLines[i]}`);
	for (let i = oldChangedEnd; i < oldEnd; i++) hunk.push(` ${oldLines[i]}`);
	return `${hunk.join("\n")}\n`;
}

export function renderReleasePlan(plan) {
	const lines = [
		"=== DRY RUN ===",
		`Scope: ${plan.scope}, version: v${plan.version}`,
		"Mode: preview only; no files, commits, tags, or pushes will be created.",
		"Files that would change:",
		...(plan.files.length > 0 ? plan.files.map((file) => `  ${file.path}`) : ["  (none)"]),
		`Commit: ${plan.commitMessage}`,
		`Tag: ${plan.tagName}`,
		"Push commands:",
		...plan.pushCommands.map((cmd) => `  ${cmd}`),
		"",
		"Diff preview:",
	];
	for (const file of plan.files) {
		lines.push(unifiedDiff(file.path, file.before, file.after).trimEnd());
	}
	return `${lines.join("\n")}\n`;
}

export function applyReleasePlan(plan, options = {}) {
	const writeFile = options.writeFile ?? writeFileSync;
	const runCommand = options.run ?? run;
	for (const file of plan.files) {
		writeFile(file.path, file.after);
	}
	if (plan.gitAddPaths.length > 0) {
		runCommand(`git add ${plan.gitAddPaths.join(" ")}`);
	}
	runCommand(`git commit -m "${plan.commitMessage}"`);
	runCommand(`git tag -a -m "${plan.tagMessage}" ${plan.tagName}`);
	for (const cmd of plan.pushCommands) runCommand(cmd);
}

export function prepareReleasePlan(plan, options = {}) {
	const writeFile = options.writeFile ?? writeFileSync;
	for (const file of plan.files) {
		writeFile(file.path, file.after);
	}
}

export function assertOnlyExpectedChanges(expectedPaths, options = {}) {
	const status =
		options.status ??
		execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" });
	const expected = new Set(expectedPaths);
	const dirtyPaths = status
		.split("\n")
		.map((line) => line.trimEnd())
		.filter(Boolean)
		.map((line) => line.slice(3));
	const unexpected = dirtyPaths.filter((path) => !expected.has(path));
	const missing = expectedPaths.filter((path) => !dirtyPaths.includes(path));
	if (unexpected.length > 0) {
		throw new Error(
			`Unexpected worktree changes during release finalize:\n${unexpected
				.map((path) => `  ${path}`)
				.join("\n")}`,
		);
	}
	if (missing.length > 0) {
		throw new Error(
			`Expected prepared release files are unchanged or missing from git status:\n${missing
				.map((path) => `  ${path}`)
				.join("\n")}`,
		);
	}
}

export function finalizeReleasePlan(plan, options = {}) {
	assertOnlyExpectedChanges(plan.expectedPaths, options);
	const runCommand = options.run ?? run;
	runCommand(`git add ${plan.gitAddPaths.join(" ")}`);
	runCommand(`git commit -m "${plan.commitMessage}"`);
	runCommand(`git tag -a -m "${plan.tagMessage}" ${plan.tagName}`);
	for (const cmd of plan.pushCommands) runCommand(cmd);
}

// Top-level only runs when invoked as a script, not when imported by tests.
if (import.meta.url === `file://${process.argv[1]}`) {
	const isDryRun = process.argv.includes("--dry-run");
	const isPrepare = process.argv.includes("--prepare");
	const isFinalize = process.argv.includes("--finalize");
	const [, , pkg, bump] = process.argv;
	const validPkgs = [...Object.keys(PACKAGES), "all"];
	const validBumps = ["patch", "minor", "major"];
	if (
		!validPkgs.includes(pkg) ||
		(isFinalize ? bump !== "--finalize" : !validBumps.includes(bump)) ||
		[isDryRun, isPrepare, isFinalize].filter(Boolean).length > 1
	) {
		console.error(
			`Usage:
  node scripts/release.mjs <${validPkgs.join("|")}> <${validBumps.join("|")}> [--dry-run|--prepare]
  node scripts/release.mjs <${validPkgs.join("|")}> --finalize

Normal mode writes files, commits, tags, and pushes in one step.
--dry-run previews only and never edits the worktree.
--prepare writes version/changelog files only so release notes can be edited.
--finalize validates prepared files, refuses unexpected worktree changes, then commits, tags, and pushes.`,
		);
		process.exit(1);
	}

	if (isFinalize) {
		const plan = createFinalizePlan(pkg);
		console.log(`\n=== FINALIZE RELEASE ===`);
		console.log(`Scope: ${plan.scope}, version: v${plan.version}`);
		console.log("Files to commit:");
		for (const path of plan.gitAddPaths) console.log(`  ${path}`);
		finalizeReleasePlan(plan);
		console.log(`\nReleased ${plan.scope === "all" ? "all packages" : `@oidfed/${plan.scope}`} at v${plan.version} → tag ${plan.tagName}`);
		process.exit(0);
	}

	const plan = createReleasePlan(pkg, bump);
	if (isDryRun) {
		process.stdout.write(renderReleasePlan(plan));
	} else if (isPrepare) {
		console.log(`\n=== PREPARE RELEASE ===`);
		console.log(`Scope: ${plan.scope}, version: v${plan.version}`);
		console.log("Files changed for manual review:");
		for (const file of plan.files) console.log(`  ${file.path}`);
		prepareReleasePlan(plan);
		console.log("\nRelease files prepared. Edit CHANGELOG content, review the diff, then run:");
		console.log(`  node scripts/release.mjs ${plan.scope} --finalize`);
	} else {
		console.log(`\n=== RELEASE ===`);
		console.log(`Scope: ${plan.scope}, version: v${plan.version}`);
		console.log("Files changed:");
		for (const file of plan.files) console.log(`  ${file.path}`);
		applyReleasePlan(plan);
		console.log(`\nReleased ${plan.scope === "all" ? "all packages" : `@oidfed/${plan.scope}`} at v${plan.version} → tag ${plan.tagName}`);
	}
}
