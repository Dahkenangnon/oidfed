/** Package releases use their own committed notes and scoped comparison links. */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
	buildBody,
	extractBreakingChanges,
	extractSectionFromText,
	PKG_FILES,
} from "./extract-changelog.mjs";
const text =
	"# Changelog\n\n## [Unreleased]\n\n## [2.1.0] - 2026-11-17\n\n**BREAKING** changed\n\n- New feature.\n\n## [2.0.0] - 2026-01-01\n\nPrevious.\n";
test("extracts exact stable and prerelease sections", () => {
	assert.equal(extractSectionFromText(text, "2.0.0"), "Previous.");
	assert.equal(extractSectionFromText(text, "2.0.1"), null);
	assert.equal(
		extractSectionFromText(text.replaceAll("2.1.0", "2.1.0-beta.1"), "2.1.0-beta.1"),
		"**BREAKING** changed\n\n- New feature.",
	);
	assert.equal(extractBreakingChanges("ordinary"), null);
});
test("builds package notes and retains historical comparison baselines", () => {
	const body = buildBody(
		"core",
		"2.1.0",
		(p) => {
			assert.equal(p, PKG_FILES.core);
			return extractSectionFromText(text, "2.1.0");
		},
		"all/v2.0.0",
	);
	assert.match(body, /BREAKING/);
	assert.match(body, /all\/v2.0.0\.\.\.core\/v2.1.0/);
	assert.match(buildBody("all", "2.1.0", () => "", "").error, /Unknown scope/);
	assert.match(buildBody("constructor", "2.1.0", () => "", "").error, /Unknown scope/);
	assert.match(buildBody("core", "2.1.0", () => null, "").error, /No section/);
});
