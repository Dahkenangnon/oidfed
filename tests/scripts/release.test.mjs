/** Verify independent release preparation and dispatch without local Git mutations. */

import assert from "node:assert/strict";
import { relative } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import {
	bumpVersion,
	createReleasePlan,
	dispatchPublication,
	main,
	parseSubject,
	prepareReleasePlan,
	renderReleasePlan,
	unifiedDiff,
	previousTagFor,
	stampChangelogText,
} from "../../scripts/release.mjs";
import { TARGETS } from "../../scripts/release/catalog.mjs";

function fixture() {
	const files = new Map(
		TARGETS.flatMap((target, index) => [
			[
				`${target.dir}/package.json`,
				JSON.stringify({ name: target.name, version: index === 1 ? "2.1.0" : "2.0.0" }),
			],
			[
				`${target.dir}/CHANGELOG.md`,
				"# Changelog\n\n## [Unreleased]\n\n## [2.0.0] - 2026-01-01\n\nPrevious.\n",
			],
		]),
	);
	return {
		files,
		options: {
			readFile: (path) => {
				const text = files.get(relative(process.cwd(), path));
				if (!text) throw Error(`Missing ${path}`);
				return text;
			},
			previousTagFor: (scope) => `${scope}/v2.0.0`,
			generateBody: (previous, path) => `### Bug Fixes\n\n* Changes to ${path} since ${previous}.`,
			date: "2026-11-17",
		},
	};
}

test("preparation keeps independent versions, scoped tags and per-package notes", () => {
	const { options } = fixture();
	const plan = createReleasePlan("all", "patch", options);
	assert.equal(plan.releases.length, 7);
	assert.equal(plan.releases[0].tag, "core/v2.0.1");
	assert.equal(plan.releases[1].tag, "authority/v2.1.1");
	assert.equal(plan.files.length, 14);
	assert.equal(
		plan.files.some((f) => ["package.json", "CHANGELOG.md"].includes(f.path)),
		false,
	);
	assert.ok(
		plan.files
			.find((f) => f.path === "packages/authority/CHANGELOG.md")
			.after.includes("authority/v2.0.0"),
	);
	assert.equal("pushCommands" in plan, false);
	assert.equal(
		plan.releases.some((r) => r.tag.startsWith("all/")),
		false,
	);
	assert.ok(renderReleasePlan(plan).includes("authority/v2.1.1"));
});

test("preparation validates every input before writing any file", () => {
	const { files, options } = fixture();
	const plan = createReleasePlan("core", "minor", options);
	const writes = new Map();
	prepareReleasePlan(plan, { writeFile: (p, s) => writes.set(p, s) });
	assert.equal(writes.size, 2);
	assert.equal(JSON.parse(writes.get("packages/core/package.json")).version, "2.1.0");
	assert.equal(unifiedDiff("x", "same\n", "same\n"), "");
	assert.match(renderReleasePlan(plan), /Diff preview/);
	files.set("packages/core/CHANGELOG.md", "# Missing marker");
	assert.throws(() => createReleasePlan("core", "patch", options), /Unreleased/);
	assert.throws(() => createReleasePlan("constructor", "patch", options), /Unknown scope/);
});

test("version bumps and conventional subjects follow supported syntax", () => {
	assert.equal(bumpVersion("2.1.0", "major"), "3.0.0");
	assert.equal(bumpVersion("2.1.0", "minor"), "2.2.0");
	assert.equal(bumpVersion("2.1.0-beta.1", "patch"), "2.1.0");
	for (const value of ["01.0.0", "v2.0.0", "2.0", "2.0.0/other"])
		assert.throws(() => bumpVersion(value, "patch"));
	assert.throws(() => bumpVersion("2.0.0", "other"), /Unsupported bump/);
	assert.deepEqual(parseSubject("fix(core)!: strict check"), {
		type: "fix",
		scope: "core",
		breaking: true,
		description: "strict check",
	});
	assert.equal(parseSubject("Merge branch"), null);
});

test("release notes preserve literal replacement tokens from commit subjects", () => {
	const body = "Keep $& and $` and $' and $$ literal.";
	assert.ok(stampChangelogText("## [Unreleased]\n", "2.0.1", body, "2026-11-17").includes(body));
});

function executor({
	dirty = "",
	origin = "https://github.com/Dahkenangnon/oidfed.git",
	ancestry = true,
} = {}) {
	const calls = [];
	return {
		calls,
		execute(command, args) {
			calls.push([command, ...args]);
			if (command === "gh") return "";
			if (args[0] === "status") return dirty;
			if (args[0] === "remote") return origin;
			if (args[0] === "rev-parse") return "a".repeat(40);
			if (args[0] === "merge-base" && !ancestry) throw Error("not on main");
			return "";
		},
	};
}

test("publication dispatch binds the clean upstream commit without creating commits or tags", () => {
	const e = executor();
	dispatchPublication("all", e);
	assert.deepEqual(e.calls.at(-1), [
		"gh",
		"workflow",
		"run",
		"release.yml",
		"--repo",
		"Dahkenangnon/oidfed",
		"--ref",
		"main",
		"-f",
		"scope=all",
		"-f",
		`source_sha=${"a".repeat(40)}`,
	]);
	assert.equal(
		e.calls.some((c) => c[0] === "git" && ["commit", "tag", "push", "add"].includes(c[1])),
		false,
	);
	const resume = executor();
	dispatchPublication(undefined, { ...resume, resumeRunId: "123" });
	assert.ok(resume.calls.at(-1).includes("resume_run_id=123"));
	for (const setup of [
		{ dirty: " M file" },
		{ origin: "https://github.com/other/repo" },
		{ ancestry: false },
	]) {
		const f = executor(setup);
		assert.throws(() => dispatchPublication("core", f));
		assert.equal(
			f.calls.some((c) => c[0] === "gh"),
			false,
		);
	}
	assert.throws(() => dispatchPublication(undefined, { resumeRunId: "../other" }), /run ID/);
});

test("retired automatic modes fail before preparation or publication", () => {
	for (const args of [
		["core", "--finalize"],
		["all", "patch"],
		["core", "patch", "--prepare", "extra"],
	])
		assert.throws(() => main(args), /review and merge/);
	const run = spawnSync(process.execPath, ["scripts/release.mjs", "all", "patch"], {
		encoding: "utf8",
	});
	assert.notEqual(run.status, 0);
	assert.match(run.stderr, /Automatic finalization is not supported/);
});

test("changelog baselines skip coordinated tags that do not describe this package", () => {
	let attempts = 0;
	const tag = previousTagFor("core", "2.1.0", {
		execute(command, args) {
			assert.equal(command, "git");
			if (args[0] === "describe") {
				attempts++;
				assert.ok(args.includes("core/v2.1.0"));
				if (attempts === 1) return "all/v2.0.0\n";
				assert.ok(args.includes("all/v2.0.0"));
				return "core/v1.9.0\n";
			}
			return JSON.stringify({ name: "@oidfed/core", version: "1.9.0" });
		},
	});
	assert.equal(tag, "core/v1.9.0");
	assert.equal(attempts, 2);
});
