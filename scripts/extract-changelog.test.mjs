import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
	PKG_FILES,
	buildBody,
	extractSectionFromText,
} from "./extract-changelog.mjs";

const SAMPLE_CHANGELOG = `# Changelog

## [Unreleased]

## [0.4.0] - 2026-05-18

### Added

- New feature foo.

### Changed

- Renamed bar.

## [0.3.0] - 2026-05-12

### Changed

- Earlier change.

## [0.2.0] - 2026-04-28

Initial.
`;

const STAMPED_EMPTY_CHANGELOG = `# Changelog

## [Unreleased]

## [0.4.1] - 2026-05-22

## [0.4.0] - 2026-05-18

- Older entry.
`;

const RC_VERSION_CHANGELOG = `# Changelog

## [Unreleased]

## [1.0.0-rc.1] - 2026-06-01

- First RC.

## [0.9.0] - 2026-05-30

- Prior.
`;

describe("extractSectionFromText", () => {
	it("extracts the section body between matching heading and next H2", () => {
		const body = extractSectionFromText(SAMPLE_CHANGELOG, "0.4.0");
		assert.equal(
			body,
			"### Added\n\n- New feature foo.\n\n### Changed\n\n- Renamed bar.",
		);
	});

	it("returns null when the version heading is not present", () => {
		assert.equal(extractSectionFromText(SAMPLE_CHANGELOG, "9.9.9"), null);
	});

	it("returns an empty string when the section heading is followed immediately by the next H2", () => {
		const body = extractSectionFromText(STAMPED_EMPTY_CHANGELOG, "0.4.1");
		assert.equal(body, "");
	});

	it("escapes regex-significant characters in the version (rc / dots)", () => {
		const body = extractSectionFromText(RC_VERSION_CHANGELOG, "1.0.0-rc.1");
		assert.equal(body, "- First RC.");
	});

	it("does not match a partial version prefix (0.4 must not match 0.4.0)", () => {
		assert.equal(extractSectionFromText(SAMPLE_CHANGELOG, "0.4"), null);
	});

	it("trims surrounding blank lines from the body", () => {
		const src = "# x\n\n## [1.2.3]\n\n\nbody line\n\n\n## [1.2.2]\n\nprev\n";
		assert.equal(extractSectionFromText(src, "1.2.3"), "body line");
	});
});

describe("buildBody — solo scope", () => {
	it("returns the matching section body with a trailing newline", () => {
		const read = (p) =>
			p === PKG_FILES.core
				? extractSectionFromText(SAMPLE_CHANGELOG, "0.4.0")
				: null;
		const out = buildBody("core", "0.4.0", read);
		assert.equal(typeof out, "string");
		assert.ok(out.endsWith("\n"));
		assert.ok(out.includes("New feature foo."));
	});

	it("returns an error object when no section matches the version", () => {
		const out = buildBody("core", "9.9.9", () => null);
		assert.deepEqual(out, {
			error: `No section [9.9.9] in ${PKG_FILES.core}`,
		});
	});

	it("returns an error object for an unknown scope", () => {
		const out = buildBody("ghost", "0.4.0", () => "body");
		assert.deepEqual(out, { error: "Unknown scope: ghost" });
	});
});

describe("buildBody — all scope", () => {
	it("emits root section, separator, then every package in fixed order", () => {
		const read = (p) => {
			if (p === "CHANGELOG.md") return "Root cross-cutting notes.";
			if (p === PKG_FILES.core) return "core body";
			if (p === PKG_FILES.authority) return "authority body";
			if (p === PKG_FILES.leaf) return "leaf body";
			if (p === PKG_FILES.oidc) return "oidc body";
			if (p === PKG_FILES.cli) return "cli body";
			return null;
		};
		const out = buildBody("all", "0.5.0", read);
		const expectedOrder = [
			"Root cross-cutting notes.",
			"---",
			"### @oidfed/core 0.5.0",
			"### @oidfed/authority 0.5.0",
			"### @oidfed/leaf 0.5.0",
			"### @oidfed/oidc 0.5.0",
			"### @oidfed/cli 0.5.0",
		];
		let cursor = -1;
		for (const needle of expectedOrder) {
			const idx = out.indexOf(needle);
			assert.ok(idx > cursor, `expected ${needle} after position ${cursor}`);
			cursor = idx;
		}
	});

	it("renders empty package sections with the placeholder", () => {
		const read = (p) => {
			if (p === "CHANGELOG.md") return null;
			if (p === PKG_FILES.core) return "core body";
			return ""; // empty stamped section
		};
		const out = buildBody("all", "0.5.0", read);
		assert.ok(out.includes("### @oidfed/core 0.5.0\n\ncore body"));
		assert.ok(out.includes("### @oidfed/authority 0.5.0\n\n_(no user-facing changes)_"));
		assert.ok(out.includes("### @oidfed/leaf 0.5.0\n\n_(no user-facing changes)_"));
		assert.ok(out.includes("### @oidfed/oidc 0.5.0\n\n_(no user-facing changes)_"));
		assert.ok(out.includes("### @oidfed/cli 0.5.0\n\n_(no user-facing changes)_"));
	});

	it("omits the separator when there is no root section", () => {
		const read = (p) => (p === "CHANGELOG.md" ? null : "x");
		const out = buildBody("all", "0.5.0", read);
		assert.ok(!out.startsWith("---"));
		assert.ok(out.startsWith("### @oidfed/core"));
	});

	it("always ends with a single trailing newline", () => {
		const read = () => "x";
		const out = buildBody("all", "0.5.0", read);
		assert.ok(out.endsWith("\n"));
		assert.ok(!out.endsWith("\n\n"));
	});
});
