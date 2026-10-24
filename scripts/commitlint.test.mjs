import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function lint(message) {
	return execFileSync("pnpm", ["exec", "commitlint"], {
		cwd: ROOT,
		encoding: "utf8",
		input: `${message}\n`,
	});
}

test("commit subjects allow 72 characters and reject 73", () => {
	const prefix = "fix(core): ";
	for (const suffix of ["", " (#116)"]) {
		assert.doesNotThrow(() =>
			lint(`${prefix}${"a".repeat(72 - prefix.length - suffix.length)}${suffix}`),
		);
		assert.throws(
			() => lint(`${prefix}${"a".repeat(73 - prefix.length - suffix.length)}${suffix}`),
			(error) => error.stdout.includes("header-max-length"),
		);
	}
});

test("one trailing reference and issue-closing body footers are accepted", () => {
	for (const prefix of ["feat(authority)", "feat(authority)!", "feat(core, authority, leaf)"])
		assert.doesNotThrow(() => lint(`${prefix}: add collection (#116)\n\nCloses #115`));
});

test("development commits can omit a subject reference", () => {
	assert.doesNotThrow(() => lint("fix(core): validate event dates\n\nCloses #115"));
	assert.doesNotThrow(() => lint("fix(core): support C#12 clients"));
});

test("URL fragments are not treated as issue references", () => {
	assert.doesNotThrow(() => lint("fix(core): preserve https://example.com/#123 fragments"));
	assert.doesNotThrow(() => lint("fix(core): preserve https://example.com/#123 (#116)"));
	assert.doesNotThrow(() => lint("fix(core): preserve https://example.com/(#123)"));
	assert.doesNotThrow(() => lint("fix(core): use https://github.com/owner/repo#115 (#116)"));
});

test("leading, embedded, and bracketed references are rejected", () => {
	for (const subject of [
		"feat(authority): #116 add subordinate events",
		"fix(core): #116 #115 validate event dates",
		"fix(core): handle [#115] validation",
		"fix(core): address #115 validation failures",
		"fix(core): validate event dates #115",
		"fix(core): preserve https://example.com/#123 [#115]",
	])
		assert.throws(
			() => lint(subject),
			(error) => error.stdout.includes("reference-position"),
		);
});

test("repository-qualified references are rejected outside the trailing reference", () => {
	for (const subject of [
		"fix(core): follow owner/repo#115 (#116)",
		"fix(core): follow owner/repo#115",
		"fix(core): follow owner-name/repo.name#115 (#116)",
		"fix(core): follow owner/repo_name#115 (#116)",
	])
		assert.throws(
			() => lint(subject),
			(error) => error.stdout.includes("reference-position"),
		);
});

test("duplicate references and reference-only subjects are rejected", () => {
	for (const subject of [
		"chore(repo): #117 enforce concise commit subjects (#117)",
		"fix(core): validate event dates (#115) (#116)",
		"fix(core): #116 add events (#115)",
		"fix(core): validate (#115) event dates",
		"fix(core): #115",
		"fix(core): (#115)",
		"fix(core):  (#115)",
	])
		assert.throws(
			() => lint(subject),
			(error) => error.stdout.includes("reference-position"),
		);
});
