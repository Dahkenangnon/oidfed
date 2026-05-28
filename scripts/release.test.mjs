import assert from "node:assert/strict";
import { test } from "node:test";

import { parseSubject } from "./release.mjs";

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
