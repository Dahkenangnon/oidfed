#!/usr/bin/env node
/**
 * Release guard: pack publishable @oidfed/* packages and inspect the packed
 * manifests/artifacts that npm would receive.
 *
 * Usage:
 *   node scripts/check-pack-manifests.mjs
 *   node scripts/check-pack-manifests.mjs --scope authority --expected-version 1.0.0
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEP_BUCKETS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];

export const NODE_ENGINE = ">=22.12.0";

export const PUBLISHABLE_TARGETS = [
	{ scope: "core", name: "@oidfed/core", dir: "packages/core", kind: "library" },
	{ scope: "authority", name: "@oidfed/authority", dir: "packages/authority", kind: "library" },
	{ scope: "leaf", name: "@oidfed/leaf", dir: "packages/leaf", kind: "library" },
	{ scope: "oidc", name: "@oidfed/oidc", dir: "packages/oidc", kind: "library" },
	{ scope: "cli", name: "@oidfed/cli", dir: "tools/cli", kind: "cli" },
];

function targetLabel(target) {
	return `${target.name} (${target.dir})`;
}

export function getTargets(scope = "all") {
	if (scope === "all") return PUBLISHABLE_TARGETS;
	const target = PUBLISHABLE_TARGETS.find((candidate) => candidate.scope === scope);
	if (!target) {
		throw new Error(
			`Unknown scope "${scope}". Expected one of: all, ${PUBLISHABLE_TARGETS.map((t) => t.scope).join(", ")}`,
		);
	}
	return [target];
}

function readOptionValue(argv, index, optionName) {
	const value = argv[index + 1];
	if (value === undefined || value.startsWith("--")) {
		throw new Error(`${optionName} requires a value`);
	}
	return value;
}

export function parseArgs(argv) {
	const args = { scope: "all", expectedVersion: undefined };
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--scope") {
			args.scope = readOptionValue(argv, i, "--scope");
			i += 1;
		} else if (arg?.startsWith("--scope=")) {
			args.scope = arg.slice("--scope=".length);
		} else if (arg === "--expected-version") {
			args.expectedVersion = readOptionValue(argv, i, "--expected-version");
			i += 1;
		} else if (arg?.startsWith("--expected-version=")) {
			args.expectedVersion = arg.slice("--expected-version=".length);
		} else if (arg === "--help" || arg === "-h") {
			args.help = true;
		} else {
			throw new Error(`Unknown argument: ${arg}`);
		}
	}
	if (!args.scope) throw new Error("--scope requires a value");
	if (args.expectedVersion === "") throw new Error("--expected-version requires a value");
	return args;
}

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function readTarString(buffer, start, length) {
	let end = start;
	const limit = start + length;
	while (end < limit && buffer[end] !== 0) end += 1;
	return buffer.subarray(start, end).toString("utf8").trim();
}

function readTarOctal(buffer, start, length) {
	const raw = readTarString(buffer, start, length).replace(/\0/g, "").trim();
	return raw === "" ? 0 : Number.parseInt(raw, 8);
}

function isZeroBlock(buffer, offset) {
	for (let i = offset; i < offset + 512; i += 1) {
		if (buffer[i] !== 0) return false;
	}
	return true;
}

export function listTgzEntries(tgzBuffer) {
	const tar = gunzipSync(tgzBuffer);
	const entries = [];
	let offset = 0;
	while (offset + 512 <= tar.length) {
		if (isZeroBlock(tar, offset)) break;
		const rawName = readTarString(tar, offset, 100);
		const prefix = readTarString(tar, offset + 345, 155);
		const name = prefix ? `${prefix}/${rawName}` : rawName;
		const size = readTarOctal(tar, offset + 124, 12);
		const dataOffset = offset + 512;
		entries.push({ name, size, dataOffset });
		offset = dataOffset + Math.ceil(size / 512) * 512;
	}
	return entries;
}

export function extractTgzText(tgzBuffer, entryName) {
	const tar = gunzipSync(tgzBuffer);
	let offset = 0;
	while (offset + 512 <= tar.length) {
		if (isZeroBlock(tar, offset)) break;
		const rawName = readTarString(tar, offset, 100);
		const prefix = readTarString(tar, offset + 345, 155);
		const name = prefix ? `${prefix}/${rawName}` : rawName;
		const size = readTarOctal(tar, offset + 124, 12);
		const dataOffset = offset + 512;
		if (name === entryName) {
			return tar.subarray(dataOffset, dataOffset + size).toString("utf8");
		}
		offset = dataOffset + Math.ceil(size / 512) * 512;
	}
	throw new Error(`Missing ${entryName} in packed tarball`);
}

function dependencyBucket(pkg, bucketName) {
	const bucket = pkg[bucketName];
	return bucket && typeof bucket === "object" && !Array.isArray(bucket) ? bucket : undefined;
}

function versionLookup(internalVersions, depName) {
	if (internalVersions instanceof Map) return internalVersions.get(depName);
	return internalVersions?.[depName];
}

function pushIfMissing(violations, condition, message) {
	if (!condition) violations.push(message);
}

export function inspectPackedManifest(pkg, target, options = {}) {
	const violations = [];
	const internalVersions = options.internalVersions ?? {};
	const expectedVersion = options.expectedVersion;
	const label = targetLabel(target);

	pushIfMissing(violations, pkg.name === target.name, `${label}: packed name is ${pkg.name}`);
	if (expectedVersion !== undefined) {
		pushIfMissing(
			violations,
			pkg.version === expectedVersion,
			`${label}: packed version is ${pkg.version}, expected ${expectedVersion}`,
		);
	}
	pushIfMissing(violations, pkg.license === "Apache-2.0", `${label}: license must be Apache-2.0`);
	pushIfMissing(violations, pkg.type === "module", `${label}: type must be module`);
	pushIfMissing(violations, pkg.main === "./dist/index.cjs", `${label}: main must be ./dist/index.cjs`);
	pushIfMissing(violations, pkg.module === "./dist/index.js", `${label}: module must be ./dist/index.js`);
	pushIfMissing(violations, pkg.types === "./dist/index.d.ts", `${label}: types must be ./dist/index.d.ts`);
	pushIfMissing(violations, pkg.exports?.["."]?.types === "./dist/index.d.ts", `${label}: exports[.].types must point to dist types`);
	pushIfMissing(violations, pkg.exports?.["."]?.import === "./dist/index.js", `${label}: exports[.].import must point to ESM build`);
	pushIfMissing(violations, pkg.exports?.["."]?.require === "./dist/index.cjs", `${label}: exports[.].require must point to CJS build`);
	pushIfMissing(violations, Array.isArray(pkg.files), `${label}: files must be an array`);
	for (const requiredFile of ["dist", "LICENSE", "NOTICE"]) {
		pushIfMissing(
			violations,
			Array.isArray(pkg.files) && pkg.files.includes(requiredFile),
			`${label}: files must include ${requiredFile}`,
		);
	}
	pushIfMissing(violations, pkg.sideEffects === false, `${label}: sideEffects must be false`);
	pushIfMissing(violations, pkg.publishConfig?.access === "public", `${label}: publishConfig.access must be public`);

	for (const bucketName of DEP_BUCKETS) {
		const bucket = dependencyBucket(pkg, bucketName);
		if (!bucket) continue;
		for (const [depName, spec] of Object.entries(bucket)) {
			if (typeof spec === "string" && spec.startsWith("workspace:")) {
				violations.push(`${label}: ${bucketName}.${depName} still uses workspace protocol`);
			}
			if (!depName.startsWith("@oidfed/")) continue;
			const expectedDepVersion = versionLookup(internalVersions, depName);
			if (expectedDepVersion === undefined) {
				violations.push(`${label}: ${bucketName}.${depName} is not a known publishable package`);
				continue;
			}
			const expectedSpec = `^${expectedDepVersion}`;
			if (spec !== expectedSpec) {
				violations.push(
					`${label}: ${bucketName}.${depName} is ${JSON.stringify(spec)}, expected ${expectedSpec}`,
				);
			}
		}
	}

	if (target.kind === "cli") {
		pushIfMissing(violations, pkg.engines?.node === NODE_ENGINE, `${label}: CLI engines.node must be ${NODE_ENGINE}`);
		pushIfMissing(violations, pkg.bin?.oidfed === "./dist/bin.js", `${label}: bin.oidfed must point to ./dist/bin.js`);
		pushIfMissing(violations, pkg.bin?.openidfed === "./dist/bin.js", `${label}: bin.openidfed must point to ./dist/bin.js`);
	} else if (pkg.engines !== undefined) {
		violations.push(`${label}: library packages are runtime-agnostic and must not publish engines`);
	}

	return violations;
}

export function requiredPackedEntries(target) {
	const entries = [
		"package/package.json",
		"package/LICENSE",
		"package/NOTICE",
		"package/dist/index.js",
		"package/dist/index.cjs",
		"package/dist/index.d.ts",
		"package/dist/index.d.cts",
	];
	if (target.kind === "cli") entries.push("package/dist/bin.js");
	return entries;
}

export function inspectPackedFiles(entries, target) {
	const entryNames = new Set(entries.map((entry) => (typeof entry === "string" ? entry : entry.name)));
	const violations = [];
	for (const requiredEntry of requiredPackedEntries(target)) {
		if (!entryNames.has(requiredEntry)) {
			violations.push(`${targetLabel(target)}: packed tarball is missing ${requiredEntry}`);
		}
	}
	return violations;
}

function resolvePackFilename(packJson, packDir) {
	const parsed = JSON.parse(packJson);
	const entry = Array.isArray(parsed) ? parsed[0] : parsed;
	if (!entry || typeof entry !== "object") throw new Error("pnpm pack --json returned no package entry");
	const filename = entry.filename ?? entry.path ?? entry.name;
	if (typeof filename !== "string" || filename.length === 0) {
		throw new Error("pnpm pack --json did not include a tarball filename");
	}
	return isAbsolute(filename) ? filename : join(packDir, filename);
}

function packTarget(target, packDir) {
	const stdout = execFileSync(
		"pnpm",
		["--dir", resolve(ROOT, target.dir), "pack", "--pack-destination", packDir, "--json"],
		{ cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
	);
	const filename = resolvePackFilename(stdout, packDir);
	if (!existsSync(filename)) throw new Error(`${targetLabel(target)}: pnpm pack did not create ${filename}`);
	return filename;
}

function usage() {
	return `Usage: node scripts/check-pack-manifests.mjs [--scope <core|authority|leaf|oidc|cli|all>] [--expected-version <version>]\n`;
}

function main() {
	let args;
	try {
		args = parseArgs(process.argv.slice(2));
		if (args.help) {
			process.stdout.write(usage());
			process.exit(0);
		}
	} catch (err) {
		process.stderr.write(`${err.message}\n${usage()}`);
		process.exit(2);
	}

	let targets;
	try {
		targets = getTargets(args.scope);
	} catch (err) {
		process.stderr.write(`${err.message}\n`);
		process.exit(2);
	}

	const internalVersions = new Map(
		PUBLISHABLE_TARGETS.map((target) => [
			target.name,
			readJson(resolve(ROOT, target.dir, "package.json")).version,
		]),
	);
	const packDir = mkdtempSync(join(tmpdir(), "oidfed-pack-manifests-"));
	const violations = [];

	try {
		for (const target of targets) {
			const tgz = packTarget(target, packDir);
			const tgzBuffer = readFileSync(tgz);
			const packedManifest = JSON.parse(extractTgzText(tgzBuffer, "package/package.json"));
			violations.push(
				...inspectPackedManifest(packedManifest, target, {
					internalVersions,
					expectedVersion: args.expectedVersion,
				}),
			);
			violations.push(...inspectPackedFiles(listTgzEntries(tgzBuffer), target));
		}
	} catch (err) {
		violations.push(err.message);
	} finally {
		rmSync(packDir, { recursive: true, force: true });
	}

	if (violations.length > 0) {
		process.stderr.write("pack manifest check FAILED:\n");
		for (const violation of violations) process.stderr.write(`  x ${violation}\n`);
		process.exit(1);
	}

	process.stdout.write(`pack manifest check OK: verified ${targets.map((t) => t.name).join(", ")}\n`);
}

const isEntry =
	import.meta.url === `file://${process.argv[1]}` ||
	import.meta.url.endsWith(process.argv[1] ?? "");
if (isEntry) main();
