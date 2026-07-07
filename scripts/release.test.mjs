import assert from "node:assert/strict";
import { relative } from "node:path";
import { test } from "node:test";

import {
	applyReleasePlan,
	assertOnlyExpectedChanges,
	bumpVersion,
	createReleasePlan,
	createFinalizePlan,
	finalizeReleasePlan,
	parseSubject,
	prepareReleasePlan,
	renderReleasePlan,
	unifiedDiff,
} from "./release.mjs";

test("parseSubject — type with scope", () => {
	const result = parseSubject("fix(cli): load version dynamically from package json");
	assert.deepEqual(result, {
		type: "fix",
		scope: "cli",
		breaking: false,
		description: "load version dynamically from package json",
	});
});

test("parseSubject — type without scope", () => {
	const result = parseSubject("feat: support trust mark delegation");
	assert.deepEqual(result, {
		type: "feat",
		scope: null,
		breaking: false,
		description: "support trust mark delegation",
	});
});

test("parseSubject — breaking marker", () => {
	const result = parseSubject("feat(core)!: drop legacy resolveTrustChain signature");
	assert.deepEqual(result, {
		type: "feat",
		scope: "core",
		breaking: true,
		description: "drop legacy resolveTrustChain signature",
	});
});

test("parseSubject — multi-word scope tolerated", () => {
	const result = parseSubject("fix(repo): some change");
	assert.equal(result.type, "fix");
	assert.equal(result.scope, "repo");
	assert.equal(result.description, "some change");
});

test("parseSubject — non-conventional subject returns null", () => {
	assert.equal(parseSubject("update files"), null);
	assert.equal(parseSubject("Merge pull request #123"), null);
	assert.equal(parseSubject("WIP: thing"), null);
});

test("parseSubject — colon without space rejected", () => {
	// Conventional commits require a space after the colon.
	assert.equal(parseSubject("fix(cli):something"), null);
});

test("bumpVersion — patch, minor, major", () => {
	assert.equal(bumpVersion("0.8.0", "patch"), "0.8.1");
	assert.equal(bumpVersion("0.8.0", "minor"), "0.9.0");
	assert.equal(bumpVersion("0.8.0", "major"), "1.0.0");
});

function pkgJson(name, version = "0.8.0") {
	return `${JSON.stringify({ name, version, private: true }, null, "\t")}\n`;
}

function changelog() {
	return "# Changelog\n\n## [Unreleased]\n\n## [0.8.0] - 2026-06-01\n\n- Previous.\n";
}

function fixtureFiles() {
	return new Map([
		["package.json", pkgJson("@oidfed/monorepo")],
		["CHANGELOG.md", changelog()],
		["packages/core/package.json", pkgJson("@oidfed/core")],
		["packages/core/CHANGELOG.md", changelog()],
		["packages/authority/package.json", pkgJson("@oidfed/authority")],
		["packages/authority/CHANGELOG.md", changelog()],
		["packages/leaf/package.json", pkgJson("@oidfed/leaf")],
		["packages/leaf/CHANGELOG.md", changelog()],
		["packages/oidc/package.json", pkgJson("@oidfed/oidc")],
		["packages/oidc/CHANGELOG.md", changelog()],
		["tools/cli/package.json", pkgJson("@oidfed/cli")],
		["tools/cli/CHANGELOG.md", changelog()],
	]);
}

function readFrom(files) {
	return (path) => {
		const key = relative(process.cwd(), path);
		const value = files.get(key);
		if (value === undefined) throw new Error(`Missing fixture file: ${key}`);
		return value;
	};
}

function releasePlanOptions(files) {
	return {
		readFile: readFrom(files),
		previousTagFor: (scope) => `${scope}/v0.8.0`,
		generateBody: (fromRef, packagePath) =>
			`### Bug Fixes\n\n* release ${packagePath} from ${fromRef}`,
		date: "2026-07-07",
	};
}

test("createReleasePlan — single package computes changed files and git metadata", () => {
	const files = fixtureFiles();
	const plan = createReleasePlan("core", "patch", releasePlanOptions(files));

	assert.equal(plan.scope, "core");
	assert.equal(plan.version, "0.8.1");
	assert.equal(plan.commitMessage, "chore(core): release v0.8.1");
	assert.equal(plan.tagName, "core/v0.8.1");
	assert.deepEqual(
		plan.files.map((file) => file.path),
		["packages/core/package.json", "packages/core/CHANGELOG.md"],
	);
	assert.ok(plan.files[0].after.includes('"version": "0.8.1"'));
	assert.ok(plan.files[1].after.includes("## [0.8.1] - 2026-07-07"));
	assert.ok(plan.files[1].after.includes("release packages/core from core/v0.8.0"));
});

test("createReleasePlan — all packages includes every package plus manual root changelog", () => {
	const files = fixtureFiles();
	const plan = createReleasePlan("all", "minor", releasePlanOptions(files));

	assert.equal(plan.scope, "all");
	assert.equal(plan.version, "0.9.0");
	assert.equal(plan.commitMessage, "chore(release): all v0.9.0");
	assert.equal(plan.tagName, "all/v0.9.0");
	assert.deepEqual(plan.files.map((file) => file.path), [
		"packages/core/package.json",
		"packages/core/CHANGELOG.md",
		"packages/authority/package.json",
		"packages/authority/CHANGELOG.md",
		"packages/leaf/package.json",
		"packages/leaf/CHANGELOG.md",
		"packages/oidc/package.json",
		"packages/oidc/CHANGELOG.md",
		"tools/cli/package.json",
		"tools/cli/CHANGELOG.md",
		"package.json",
		"CHANGELOG.md",
	]);
	const rootChangelog = plan.files.find((file) => file.path === "CHANGELOG.md");
	assert.match(rootChangelog.after, /## \[0\.9\.0\] - 2026-07-07\n+\s*## \[0\.8\.0\]/);
	assert.ok(!rootChangelog.after.includes("release package"));
});

test("renderReleasePlan — dry run previews summary and diff without side effects", () => {
	const files = fixtureFiles();
	const plan = createReleasePlan("core", "patch", releasePlanOptions(files));
	const out = renderReleasePlan(plan);

	assert.ok(out.includes("Mode: preview only"));
	assert.ok(out.includes("packages/core/package.json"));
	assert.ok(out.includes("diff --git a/packages/core/package.json b/packages/core/package.json"));
	assert.ok(out.includes('+\t"version": "0.8.1"'));
	assert.ok(out.includes("### Bug Fixes"));
});

test("unifiedDiff — returns empty string when file content is unchanged", () => {
	assert.equal(unifiedDiff("package.json", "same\n", "same\n"), "");
});

test("applyReleasePlan — writes planned content then runs git commands", () => {
	const files = fixtureFiles();
	const plan = createReleasePlan("core", "patch", releasePlanOptions(files));
	const writes = new Map();
	const commands = [];

	applyReleasePlan(plan, {
		writeFile: (path, content) => writes.set(path, content),
		run: (cmd) => commands.push(cmd),
	});

	assert.equal(writes.size, 2);
	assert.ok(writes.get("packages/core/package.json").includes('"version": "0.8.1"'));
	assert.deepEqual(commands, [
		"git add packages/core/package.json packages/core/CHANGELOG.md",
		'git commit -m "chore(core): release v0.8.1"',
		'git tag -a -m "release: @oidfed/core v0.8.1" core/v0.8.1',
		"git push",
		"git push origin core/v0.8.1",
	]);
});

test("prepareReleasePlan — writes files without running git commands", () => {
	const files = fixtureFiles();
	const plan = createReleasePlan("core", "patch", releasePlanOptions(files));
	const writes = new Map();

	prepareReleasePlan(plan, {
		writeFile: (path, content) => writes.set(path, content),
	});

	assert.deepEqual([...writes.keys()], ["packages/core/package.json", "packages/core/CHANGELOG.md"]);
	assert.ok(writes.get("packages/core/package.json").includes('"version": "0.8.1"'));
});

test("createFinalizePlan — validates prepared files and builds git metadata", () => {
	const files = fixtureFiles();
	const prepared = createReleasePlan("core", "patch", releasePlanOptions(files));
	for (const file of prepared.files) files.set(file.path, file.after);

	const plan = createFinalizePlan("core", { readFile: readFrom(files) });

	assert.equal(plan.scope, "core");
	assert.equal(plan.version, "0.8.1");
	assert.deepEqual(plan.expectedPaths, ["packages/core/package.json", "packages/core/CHANGELOG.md"]);
	assert.equal(plan.commitMessage, "chore(core): release v0.8.1");
	assert.equal(plan.tagName, "core/v0.8.1");
});

test("createFinalizePlan — rejects missing prepared changelog section", () => {
	const files = fixtureFiles();
	files.set("packages/core/package.json", pkgJson("@oidfed/core", "0.8.1"));

	assert.throws(
		() => createFinalizePlan("core", { readFile: readFrom(files) }),
		/missing ## \[0\.8\.1\]/,
	);
});

test("assertOnlyExpectedChanges — rejects unexpected dirty files", () => {
	assert.throws(
		() =>
			assertOnlyExpectedChanges(["packages/core/package.json"], {
				status: " M packages/core/package.json\n M scripts/release.mjs\n",
			}),
		/Unexpected worktree changes/,
	);
});

test("assertOnlyExpectedChanges — rejects missing expected dirty files", () => {
	assert.throws(
		() =>
			assertOnlyExpectedChanges(["packages/core/package.json", "packages/core/CHANGELOG.md"], {
				status: " M packages/core/package.json\n",
			}),
		/Expected prepared release files/,
	);
});

test("finalizeReleasePlan — validates status then runs git commands only", () => {
	const files = fixtureFiles();
	const prepared = createReleasePlan("core", "patch", releasePlanOptions(files));
	for (const file of prepared.files) files.set(file.path, file.after);
	const plan = createFinalizePlan("core", { readFile: readFrom(files) });
	const commands = [];

	finalizeReleasePlan(plan, {
		status: " M packages/core/package.json\n M packages/core/CHANGELOG.md\n",
		run: (cmd) => commands.push(cmd),
	});

	assert.deepEqual(commands, [
		"git add packages/core/package.json packages/core/CHANGELOG.md",
		'git commit -m "chore(core): release v0.8.1"',
		'git tag -a -m "release: @oidfed/core v0.8.1" core/v0.8.1',
		"git push",
		"git push origin core/v0.8.1",
	]);
});
