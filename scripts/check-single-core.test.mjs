import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { inspectPackage } from "./check-single-core.mjs";

const CORE_PKG = {
	name: "@oidfed/core",
	version: "0.4.0",
};

const AUTHORITY_OK_PEER = {
	name: "@oidfed/authority",
	version: "0.4.0",
	peerDependencies: { "@oidfed/core": "workspace:^" },
};

const LEAF_OK_PEER = {
	name: "@oidfed/leaf",
	version: "0.4.0",
	peerDependencies: { "@oidfed/core": "workspace:^" },
};

const CLI_OK_DEP = {
	name: "@oidfed/cli",
	version: "0.4.0",
	dependencies: { "@oidfed/core": "workspace:^" },
};

const LEGACY_LEAF_HARDCODED = {
	name: "@oidfed/leaf",
	version: "0.3.0",
	dependencies: { "@oidfed/core": "0.3.0" },
};

const AUTHORITY_HARDCODED_PEER = {
	name: "@oidfed/authority",
	version: "0.4.0",
	peerDependencies: { "@oidfed/core": "^0.4.0" },
};

const BOTH_DEPS_AND_PEERS = {
	name: "@oidfed/authority",
	version: "0.4.0",
	dependencies: { "@oidfed/core": "workspace:^" },
	peerDependencies: { "@oidfed/core": "workspace:^" },
};

const CORE_WITH_SELF_REF = {
	name: "@oidfed/core",
	version: "0.4.0",
	dependencies: { "@oidfed/core": "workspace:^" },
};

describe("inspectPackage — compliant configurations", () => {
	it("accepts @oidfed/core itself with no self-reference", () => {
		assert.deepEqual(inspectPackage(CORE_PKG, "packages/core/package.json"), []);
	});

	it("accepts workspace:^ in peerDependencies", () => {
		assert.deepEqual(
			inspectPackage(AUTHORITY_OK_PEER, "packages/authority/package.json"),
			[],
		);
	});

	it("accepts workspace:^ in dependencies (cli case)", () => {
		assert.deepEqual(
			inspectPackage(CLI_OK_DEP, "tools/cli/package.json"),
			[],
		);
	});

	it("accepts workspace:* as well", () => {
		const pkg = {
			name: "@oidfed/authority",
			version: "0.4.0",
			peerDependencies: { "@oidfed/core": "workspace:*" },
		};
		assert.deepEqual(inspectPackage(pkg, "packages/authority/package.json"), []);
	});
});

describe("inspectPackage — violations", () => {
	it("flags a hardcoded exact version in dependencies (the leaf@0.3.0 incident)", () => {
		const out = inspectPackage(
			LEGACY_LEAF_HARDCODED,
			"packages/leaf/package.json",
		);
		assert.equal(out.length, 1);
		assert.match(out[0], /@oidfed\/leaf declares @oidfed\/core in dependencies as "0\.3\.0"/);
		assert.match(out[0], /workspace: protocol/);
	});

	it("flags a hardcoded caret range in peerDependencies", () => {
		const out = inspectPackage(
			AUTHORITY_HARDCODED_PEER,
			"packages/authority/package.json",
		);
		assert.equal(out.length, 1);
		assert.match(out[0], /\^0\.4\.0/);
	});

	it("flags declaring @oidfed/core in BOTH dependencies and peerDependencies", () => {
		const out = inspectPackage(
			BOTH_DEPS_AND_PEERS,
			"packages/authority/package.json",
		);
		const both = out.find((v) => v.includes("BOTH dependencies and peerDependencies"));
		assert.ok(both, `expected a 'BOTH' violation, got: ${JSON.stringify(out)}`);
	});

	it("flags @oidfed/core declaring a self-reference", () => {
		const out = inspectPackage(CORE_WITH_SELF_REF, "packages/core/package.json");
		assert.equal(out.length, 1);
		assert.match(out[0], /self-reference/);
	});
});

describe("inspectPackage — irrelevant deps are ignored", () => {
	it("does not flag non-core deps", () => {
		const pkg = {
			name: "@oidfed/oidc",
			version: "0.4.0",
			dependencies: { zod: "^4.0.0" },
			peerDependencies: { "@oidfed/core": "workspace:^" },
		};
		assert.deepEqual(inspectPackage(pkg, "packages/oidc/package.json"), []);
	});

	it("returns empty array when no dependency buckets exist", () => {
		const pkg = { name: "@oidfed/core", version: "0.4.0" };
		assert.deepEqual(inspectPackage(pkg, "packages/core/package.json"), []);
	});
});
