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
	assert.doesNotThrow(() => lint(`${prefix}${"a".repeat(72 - prefix.length)}`));
	assert.throws(
		() => lint(`${prefix}${"a".repeat(73 - prefix.length)}`),
		(error) => error.stdout.includes("header-max-length"),
	);
});

test("early references and issue-closing body footers are accepted", () => {
	for (const prefix of ["feat(authority)", "feat(authority)!"])
		assert.doesNotThrow(() => lint(`${prefix}: #116 add subordinate events\n\nCloses #115`));
	assert.doesNotThrow(() => lint("fix(core): #116 #115 validate event dates"));
});

test("development commits can omit a subject reference", () => {
	assert.doesNotThrow(() => lint("fix(core): validate event dates\n\nCloses #115"));
});

test("URL fragments are not treated as issue references", () => {
	assert.doesNotThrow(() => lint("fix(core): preserve https://example.com/#123 fragments"));
	assert.doesNotThrow(() => lint("fix(core): #116 preserve https://example.com/#123 fragments"));
});

test("bracketed references and references after the description are rejected", () => {
	for (const subject of [
		"fix(core): handle [#115] validation",
		"fix(core): #116 add events (#115)",
		"fix(core): #116 handle [#115] validation",
		"fix(core): preserve https://example.com/#123 [#115]",
	])
		assert.throws(
			() => lint(subject),
			(error) => error.stdout.includes("reference-position"),
		);
});

test("trailing and embedded numbered references are rejected", () => {
	for (const subject of [
		"feat(authority): add subordinate events (#116)",
		"fix(core): address #115 validation failures",
		"fix(core): #115",
	])
		assert.throws(
			() => lint(subject),
			(error) => error.stdout.includes("reference-position"),
		);
});
