#!/usr/bin/env node
/** Prepare reviewed package releases or dispatch publication of committed versions. */

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { getTargets, REPOSITORY, version } from "./release/catalog.mjs";

const REMOTE = `https://github.com/${REPOSITORY}`;

// Ordinary release notes include user-facing changes. A breaking marker takes priority.
const TYPE_TO_HEADING = {
	feat: "### Features",
	fix: "### Bug Fixes",
	perf: "### Performance",
	refactor: "### Refactor",
};

const BREAKING_HEADING = "### Breaking Changes";
const HEADING_ORDER = [
	BREAKING_HEADING,
	"### Features",
	"### Bug Fixes",
	"### Performance",
	"### Refactor",
];

function readText(path, readFile = readFileSync) {
	return readFile(resolve(path), "utf8");
}

function updateJsonVersion(src, version) {
	const json = JSON.parse(src);
	json.version = version;
	return `${JSON.stringify(json, null, "\t")}\n`;
}

export function bumpVersion(value, bump) {
	version(value);
	if (!["major", "minor", "patch"].includes(bump)) throw new Error(`Unsupported bump: ${bump}`);
	return semver.inc(value, bump);
}

/** Find the nearest scoped or applicable historical coordinated release. */
export function previousTagFor(scope, excludeVersion, { execute = execFileSync } = {}) {
	const target = getTargets(scope)[0];
	const excluded = excludeVersion ? [`${scope}/v${excludeVersion}`, `all/v${excludeVersion}`] : [];
	for (let attempt = 0; attempt < 1000; attempt++) {
		let tag;
		try {
			tag = execute(
				"git",
				[
					"describe",
					"--tags",
					"--match",
					`${scope}/v*.*.*`,
					"--match",
					"all/v*.*.*",
					"--abbrev=0",
					...excluded.flatMap((value) => ["--exclude", value]),
					"HEAD",
				],
				{ encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
			).trim();
		} catch {
			return "";
		}
		try {
			const manifest = JSON.parse(
				execute("git", ["show", `${tag}:${target.dir}/package.json`], {
					encoding: "utf8",
					stdio: ["ignore", "pipe", "ignore"],
				}),
			);
			if (
				manifest.name === target.name &&
				`${tag.startsWith("all/") ? "all" : scope}/v${version(manifest.version)}` === tag
			)
				return tag;
		} catch {
			/* Tags predating a package or describing another version are not its baseline. */
		}
		if (excluded.includes(tag)) throw new Error("Git returned an excluded release tag");
		excluded.push(tag);
	}
	throw new Error("Release tag search limit exceeded");
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
export function generateBody(fromRef, packagePath, { execute = execFileSync } = {}) {
	const range = fromRef ? `${fromRef}..HEAD` : "HEAD";
	const args = ["log", "--no-merges", "--pretty=format:%H%x09%s", range];
	if (packagePath) args.push("--", packagePath);
	const out = execute("git", args, { encoding: "utf8" })
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
		const heading = parsed.breaking ? BREAKING_HEADING : TYPE_TO_HEADING[parsed.type];
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
export function stampChangelogText(src, value, body, date) {
	const marker = "## [Unreleased]";
	const rendered = body || "_No user-visible changes in this package._";
	return src.replace(marker, () => `${marker}\n\n## [${value}] - ${date}\n\n${rendered}\n`);
}

function changedFile(path, before, after) {
	return before === after ? null : { path, before, after };
}

export function createReleasePlan(scope, bump, options = {}) {
	const readFile = options.readFile ?? readFileSync;
	const previousTag = options.previousTagFor ?? previousTagFor;
	const bodyGenerator = options.generateBody ?? generateBody;
	const date = options.date ?? new Date().toISOString().slice(0, 10);
	const files = [];
	const releases = [];
	for (const target of getTargets(scope)) {
		const path = `${target.dir}/package.json`;
		const before = readText(path, readFile);
		const manifest = JSON.parse(before);
		if (manifest.name !== target.name) throw new Error(`Package identity mismatch in ${path}`);
		const next = bumpVersion(manifest.version, bump);
		const previous = previousTag(target.scope);
		releases.push({ ...target, version: next, tag: `${target.scope}/v${next}` });
		const change = changedFile(path, before, updateJsonVersion(before, next));
		if (change) files.push(change);
		const changelogPath = `${target.dir}/CHANGELOG.md`;
		const changelog = readText(changelogPath, readFile);
		if (!changelog.includes("## [Unreleased]"))
			throw new Error(`Missing Unreleased section in ${changelogPath}`);
		if (changelog.split(/\r?\n/).some((line) => line.startsWith(`## [${next}]`)))
			throw new Error(`Changelog already contains ${next}`);
		const updated = stampChangelogText(changelog, next, bodyGenerator(previous, target.dir), date);
		files.push(changedFile(changelogPath, changelog, updated));
	}
	return { scope, releases, files: files.filter(Boolean) };
}

export function prepareReleasePlan(plan, options = {}) {
	const writeFile = options.writeFile ?? writeFileSync;
	for (const file of plan.files) writeFile(file.path, file.after);
}

/** No local Git mutation: dispatch only after the reviewed commit is on origin/main. */
export function dispatchPublication(scope, { resumeRunId, execute = execFileSync } = {}) {
	if (resumeRunId !== undefined && !/^[1-9]\d*$/.test(resumeRunId))
		throw new Error("Invalid release run ID");
	if (!resumeRunId) getTargets(scope);
	const git = (...args) => execute("git", args, { encoding: "utf8" }).trim();
	if (git("status", "--porcelain"))
		throw new Error("Commit or set aside local changes before publication");
	const origin = git("remote", "get-url", "origin");
	if (![`${REMOTE}.git`, REMOTE, `git@github.com:${REPOSITORY}.git`].includes(origin))
		throw new Error("Release origin must be the upstream repository");
	git("fetch", "--no-tags", "origin", "main");
	const sha = git("rev-parse", "HEAD");
	git("merge-base", "--is-ancestor", sha, "refs/remotes/origin/main");
	const fields = resumeRunId
		? ["-f", `resume_run_id=${resumeRunId}`]
		: ["-f", `scope=${scope}`, "-f", `source_sha=${sha}`];
	execute(
		"gh",
		["workflow", "run", "release.yml", "--repo", REPOSITORY, "--ref", "main", ...fields],
		{ stdio: "inherit" },
	);
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
		"Mode: preview only; no files, commits, tags, or pushes will be created.",
		...plan.releases.map((entry) => `${entry.name}: ${entry.version} → ${entry.tag}`),
		"",
		"Diff preview:",
	];
	for (const file of plan.files)
		lines.push(unifiedDiff(file.path, file.before, file.after).trimEnd());
	return `${lines.join("\n")}\n`;
}

export function main(args = process.argv.slice(2)) {
	if (args.length === 2 && args[0] === "--resume") {
		dispatchPublication(undefined, { resumeRunId: args[1] });
		return;
	}
	const [scope, mode, flag] = args;
	if (args.length === 2 && mode === "--publish") {
		dispatchPublication(scope);
		return;
	}
	if (args.length !== 3 || !["--dry-run", "--prepare"].includes(flag))
		throw new Error(
			"Use: pnpm release <package|all> <patch|minor|major> --dry-run|--prepare; then review and merge, and run pnpm release <package|all> --publish. Resume with pnpm release --resume <run-id>. Automatic finalization is not supported.",
		);
	const plan = createReleasePlan(scope, mode);
	if (flag === "--dry-run") process.stdout.write(renderReleasePlan(plan));
	else {
		prepareReleasePlan(plan);
		console.log(
			"Prepared package versions and changelogs. Review, commit, and merge these changes before publishing.",
		);
		for (const entry of plan.releases)
			console.log(`${entry.name}: ${entry.version} → ${entry.tag}`);
	}
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	try {
		main();
	} catch (error) {
		console.error(error.message);
		process.exitCode = 1;
	}
}
