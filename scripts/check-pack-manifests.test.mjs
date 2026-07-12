import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
	inspectPackedFiles,
	inspectPackedManifest,
	NODE_ENGINE,
	parseArgs,
	PUBLISHABLE_TARGETS,
	requiredPackedEntries,
} from "./check-pack-manifests.mjs";

const targets = Object.fromEntries(PUBLISHABLE_TARGETS.map((target) => [target.scope, target]));
const internalVersions = {
	"@oidfed/core": "0.8.0",
	"@oidfed/authority": "0.8.0",
	"@oidfed/leaf": "0.8.0",
	"@oidfed/oidc": "0.8.0",
	"@oidfed/cli": "0.8.0",
};

function baseManifest(target, overrides = {}) {
	const manifest = {
		name: target.name,
		version: "0.8.0",
		license: "Apache-2.0",
		type: "module",
		main: "./dist/index.cjs",
		module: "./dist/index.js",
		types: "./dist/index.d.ts",
		exports: {
			".": {
				types: "./dist/index.d.ts",
				import: "./dist/index.js",
				require: "./dist/index.cjs",
			},
		},
		files: ["dist", "LICENSE", "NOTICE"],
		sideEffects: false,
		publishConfig: { access: "public" },
	};
	if (target.kind === "cli") {
		manifest.engines = { node: NODE_ENGINE };
		manifest.bin = { oidfed: "./dist/bin.js", openidfed: "./dist/bin.js" };
	}
	return { ...manifest, ...overrides };
}

function inspect(manifest, target = targets.authority, options = {}) {
	return inspectPackedManifest(manifest, target, { internalVersions, ...options });
}

describe("parseArgs", () => {
	it("rejects missing option values", () => {
		assert.throws(() => parseArgs(["--scope"]), /--scope requires a value/);
		assert.throws(() => parseArgs(["--expected-version"]), /--expected-version requires a value/);
	});
});

describe("inspectPackedManifest", () => {
	it("accepts packed manifests with pnpm-rewritten internal dependency ranges", () => {
		const manifest = baseManifest(targets.authority, {
			devDependencies: { "@oidfed/core": "^0.8.0" },
			peerDependencies: { "@oidfed/core": "^0.8.0" },
		});

		assert.deepEqual(inspect(manifest), []);
	});

	it("rejects workspace protocol ranges in packed manifests", () => {
		const manifest = baseManifest(targets.leaf, {
			peerDependencies: { "@oidfed/core": "workspace:^" },
		});

		const out = inspect(manifest, targets.leaf);
		assert.equal(out.length, 2);
		assert.ok(out.some((violation) => violation.includes("still uses workspace protocol")));
		assert.ok(out.some((violation) => violation.includes("expected ^0.8.0")));
	});

	it("rejects stale internal dependency ranges", () => {
		const manifest = baseManifest(targets.oidc, {
			dependencies: { zod: "4.4.3" },
			peerDependencies: { "@oidfed/core": "^0.7.0" },
		});

		const out = inspect(manifest, targets.oidc);
		assert.equal(out.length, 1);
		assert.match(out[0], /expected \^0\.8\.0/);
	});

	it("rejects missing packed entrypoint metadata", () => {
		const manifest = baseManifest(targets.core, { exports: {} });

		const out = inspect(manifest, targets.core);
		assert.ok(out.some((violation) => violation.includes("exports[.].types")));
		assert.ok(out.some((violation) => violation.includes("exports[.].import")));
		assert.ok(out.some((violation) => violation.includes("exports[.].require")));
	});

	it("enforces the CLI-only Node engine policy", () => {
		const library = baseManifest(targets.core, { engines: { node: NODE_ENGINE } });
		assert.ok(inspect(library, targets.core).some((violation) => violation.includes("must not publish engines")));

		const cliWithoutEngine = baseManifest(targets.cli, { engines: undefined });
		assert.ok(
			inspect(cliWithoutEngine, targets.cli).some((violation) =>
				violation.includes("CLI engines.node"),
			),
		);

		const cli = baseManifest(targets.cli, {
			dependencies: { "@oidfed/core": "^0.8.0" },
		});
		assert.deepEqual(inspect(cli, targets.cli), []);
	});

	it("rejects a tag version that does not match the packed manifest", () => {
		const manifest = baseManifest(targets.core);
		const out = inspect(manifest, targets.core, { expectedVersion: "1.0.0" });

		assert.equal(out.length, 1);
		assert.match(out[0], /expected 1\.0\.0/);
	});
});

describe("inspectPackedFiles", () => {
	it("accepts the required library artifacts", () => {
		assert.deepEqual(inspectPackedFiles(requiredPackedEntries(targets.core), targets.core), []);
	});

	it("rejects missing dist/type artifacts", () => {
		const entries = requiredPackedEntries(targets.core).filter(
			(entry) => entry !== "package/dist/index.d.cts",
		);

		const out = inspectPackedFiles(entries, targets.core);
		assert.equal(out.length, 1);
		assert.match(out[0], /index\.d\.cts/);
	});

	it("requires the CLI binary artifact", () => {
		const entries = requiredPackedEntries(targets.cli).filter(
			(entry) => entry !== "package/dist/bin.js",
		);

		const out = inspectPackedFiles(entries, targets.cli);
		assert.equal(out.length, 1);
		assert.match(out[0], /dist\/bin\.js/);
	});
});
