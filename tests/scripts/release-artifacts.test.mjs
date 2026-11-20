/** Release bundles bind saved bytes, versions and notes to the verified source. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { archive, bundle, SHA } from "./fixtures/release.mjs";
import { loadArtifacts, inspectArchive } from "../../scripts/release/artifacts.mjs";
import { parseTag, publicationOrder, TARGETS } from "../../scripts/release/catalog.mjs";

import { stageLibraryArchives } from "../../scripts/check-crypto-isolation.mjs";

test("saved archives retain per-package identities and reject mutation or foreign origins", () => {
	const parent = mkdtempSync(join(tmpdir(), "oidfed-release-bundle-")),
		dir = join(parent, "bundle");
	try {
		const manifest = bundle(dir);
		assert.equal(loadArtifacts(dir, { sourceSha: SHA, runId: "123" }).packages.length, 7);
		const saved = readFileSync(join(dir, "manifest.json"));
		const core = manifest.packages.find((p) => p.scope === "core");
		const original = readFileSync(join(dir, core.file));
		writeFileSync(join(dir, core.file), "tampered");
		assert.throws(() => loadArtifacts(dir), /integrity/);
		writeFileSync(join(dir, core.file), original);
		for (const mutate of [
			(m) => (m.repository = "other/repo"),
			(m) => (m.sourceSha = "wrong"),
			(m) => (m.packages[0].file = "../escape.tgz"),
			(m) => (m.packages[0].name = "other"),
			(m) => (m.selected = ["all"]),
			(m) => (m.selected = ["core", "core"]),
			(m) => (m.packages[0].tag = "all/v2.0.0"),
		]) {
			const bad = JSON.parse(saved);
			mutate(bad);
			writeFileSync(join(dir, "manifest.json"), JSON.stringify(bad));
			assert.throws(() => loadArtifacts(dir));
		}
		writeFileSync(join(dir, "manifest.json"), saved);
		assert.throws(() => loadArtifacts(dir, { runId: "999" }), /origin/);
		writeFileSync(join(dir, "core.md"), "changed");
		assert.throws(() => loadArtifacts(dir), /notes integrity/);
	} finally {
		rmSync(parent, { recursive: true, force: true });
	}
});

test("archive validation rejects traversal, links, duplicate names and malformed headers", () => {
	const target = TARGETS[0];
	for (const entries of [
		[["package/../../escape", "x"]],
		[["package/link", "outside", 50]],
		[
			["package/x", "one"],
			["package/x", "two"],
		],
	])
		assert.throws(() => inspectArchive(archive(entries), target, {}), /Unsafe|Duplicate/);
	const invalid = archive([["package/x", "x"]]);
	assert.throws(() => inspectArchive(invalid, target, {}), /Missing|missing/);
});

test("release tags and dependencies are validated independently of input order", () => {
	assert.equal(parseTag("authority/v2.1.1").scope, "authority");
	for (const tag of ["all/v2.0.0", "constructor/v2.0.0", "core/v01.0.0", "core/v2.0.0/extra"])
		assert.throws(() => parseTag(tag));
	const core = { name: "@oidfed/core", version: "2.0.0", dependencies: {} };
	const dependent = {
		name: "@oidfed/authority",
		version: "2.1.1",
		dependencies: { "@oidfed/core": "^2.0.0" },
	};
	assert.deepEqual(publicationOrder([dependent, core]), [core, dependent]);
	assert.throws(
		() => publicationOrder([{ ...dependent, dependencies: { "@oidfed/core": "^3.0.0" } }, core]),
		/requires/,
	);
	assert.throws(() => publicationOrder([core, core]), /Duplicate/);
	assert.throws(
		() =>
			publicationOrder([{ ...core, dependencies: { "@oidfed/authority": "^2.0.0" } }, dependent]),
		/Cyclic/,
	);
});

test("the consumer uses the saved bytes of all library archives", () => {
	const parent = mkdtempSync(join(tmpdir(), "oidfed-release-consumer-"));
	try {
		const directory = join(parent, "bundle");
		const consumer = join(parent, "consumer");
		mkdirSync(consumer);
		const { packages } = bundle(directory);
		const libraries = packages.filter(({ scope }) => scope !== "cli");
		const paths = Object.fromEntries(libraries.map(({ scope, file }) => [scope, join(directory, file)]));
		const staged = stageLibraryArchives(consumer, paths);
		assert.equal(Object.keys(staged).length, 6);
		for (const { scope, name } of libraries) {
			assert.equal(staged[name], "file:./" + scope + ".tgz");
			assert.deepEqual(readFileSync(join(consumer, scope + ".tgz")), readFileSync(paths[scope]));
		}
		const { wallet: _missing, ...incomplete } = paths;
		assert.throws(() => stageLibraryArchives(consumer, incomplete), /Missing saved wallet tarball/);
	} finally {
		rmSync(parent, { recursive: true, force: true });
	}
});

test("a v3 batch accepts Crypto 1.0.0 and publishes it before Core", () => {
	const crypto = { name: "@oidfed/crypto", version: "1.0.0", dependencies: {} };
	const core = { name: "@oidfed/core", version: "3.0.0", dependencies: { "@oidfed/crypto": "^1.0.0" } };
	assert.deepEqual(publicationOrder([core, crypto]), [crypto, core]);
});
