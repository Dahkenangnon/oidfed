/** Save and verify the exact archives handed from release validation to publication. */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, readdirSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { TARGETS, getTargets, REPOSITORY, WORKFLOW, version, distributionTag } from "./catalog.mjs";
import {
	extractTgzText,
	listTgzEntries,
	inspectPackedManifest,
	inspectPackedFiles,
} from "../check-pack-manifests.mjs";

export const integrity = (bytes) => `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const validSha = (value) => typeof value === "string" && /^[a-f0-9]{40}$/.test(value);

export function inspectArchive(bytes, target, options) {
	const entries = listTgzEntries(bytes);
	if (new Set(entries.map((entry) => entry.name)).size !== entries.length)
		throw new Error("Duplicate archive entries");
	for (const entry of entries) {
		if (
			![0, 48, 53].includes(entry.type) ||
			!entry.name.startsWith("package/") ||
			entry.name.includes("\\") ||
			entry.name.split("/").some((p) => p === ".." || p === ".")
		)
			throw new Error("Unsafe archive path");
	}
	const manifest = JSON.parse(extractTgzText(bytes, "package/package.json"));
	const violations = [
		...inspectPackedManifest(manifest, target, options),
		...inspectPackedFiles(entries, target),
	];
	if (violations.length) throw new Error(violations.join("\n"));
	return manifest;
}

/** Pack every publishable package once; the selection controls publication, not test coverage. */
export function createArtifacts({
	directory,
	scope,
	sourceSha,
	workflowSha,
	runId,
	notes,
	execute = execFileSync,
}) {
	if (!validSha(sourceSha) || !validSha(workflowSha) || !/^[1-9]\d*$/.test(String(runId)))
		throw new Error("Invalid artifact origin");
	const selected = getTargets(scope).map((p) => p.scope);
	mkdirSync(directory, { recursive: true });
	if (readdirSync(directory).length) throw new Error("Artifact output must be empty");
	const internalVersions = Object.fromEntries(
		TARGETS.map((p) => [
			p.name,
			version(JSON.parse(readFileSync(`${p.dir}/package.json`, "utf8")).version),
		]),
	);
	const packages = [];
	for (const target of TARGETS) {
		const output = join(directory, target.scope);
		mkdirSync(output);
		execute("pnpm", ["--dir", resolve(target.dir), "pack", "--pack-destination", resolve(output)], {
			stdio: "inherit",
		});
		const files = readdirSync(output);
		if (files.length !== 1 || !files[0].endsWith(".tgz"))
			throw new Error(`Expected one archive for ${target.name}`);
		const bytes = readFileSync(join(output, files[0]));
		const manifest = inspectArchive(bytes, target, {
			internalVersions,
			expectedVersion: internalVersions[target.name],
		});
		const text = selected.includes(target.scope) ? notes(target, manifest.version) : "";
		if (typeof text !== "string" || (selected.includes(target.scope) && !text.trim()))
			throw new Error(`Missing release notes for ${target.name}`);
		writeFileSync(join(directory, `${target.scope}.md`), text);
		packages.push({
			scope: target.scope,
			name: target.name,
			version: manifest.version,
			tag: `${target.scope}/v${manifest.version}`,
			file: `${target.scope}/${files[0]}`,
			integrity: integrity(bytes),
			notesSha256: sha256(text),
			distTag: distributionTag(manifest.version),
			dependencies: Object.fromEntries(
				Object.entries({
					...manifest.dependencies,
					...manifest.peerDependencies,
					...manifest.optionalDependencies,
				}).filter(([name]) => name.startsWith("@oidfed/")),
			),
		});
	}
	const manifest = {
		format: 1,
		repository: REPOSITORY,
		workflow: WORKFLOW,
		sourceSha,
		workflowSha,
		runId: String(runId),
		selected,
		internalVersions,
		packages,
	};
	writeFileSync(join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	loadArtifacts(directory, { sourceSha, runId: String(runId) });
	return manifest;
}

/** Validate untrusted downloaded metadata and archive bytes before using any paths or identities. */
export function loadArtifacts(directory, expected = {}) {
	if (!lstatSync(join(directory, "manifest.json")).isFile())
		throw new Error("Invalid artifact manifest file");
	const manifest = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8"));
	if (
		manifest.format !== 1 ||
		manifest.repository !== REPOSITORY ||
		manifest.workflow !== WORKFLOW ||
		!validSha(manifest.sourceSha) ||
		!validSha(manifest.workflowSha) ||
		typeof manifest.runId !== "string" ||
		!/^[1-9]\d*$/.test(manifest.runId) ||
		(expected.sourceSha && manifest.sourceSha !== expected.sourceSha) ||
		(expected.runId && manifest.runId !== expected.runId)
	)
		throw new Error("Artifact origin mismatch");
	if (
		!Array.isArray(manifest.selected) ||
		!manifest.selected.length ||
		new Set(manifest.selected).size !== manifest.selected.length
	)
		throw new Error("Invalid release selection");
	for (const scope of manifest.selected)
		if (scope === "all" || getTargets(scope).length !== 1)
			throw new Error("Invalid package selection");
	if (
		!Array.isArray(manifest.packages) ||
		manifest.packages.length !== TARGETS.length ||
		new Set(manifest.packages.map((p) => p.scope)).size !== TARGETS.length
	)
		throw new Error("Invalid artifact package inventory");
	if (
		!manifest.internalVersions ||
		Object.keys(manifest.internalVersions).sort().join() !==
			TARGETS.map((p) => p.name)
				.sort()
				.join()
	)
		throw new Error("Invalid artifact version inventory");
	for (const target of TARGETS) {
		const entry = manifest.packages.find((p) => p.scope === target.scope);
		if (
			!entry ||
			entry.name !== target.name ||
			version(entry.version) !== manifest.internalVersions?.[target.name] ||
			entry.tag !== `${target.scope}/v${entry.version}` ||
			entry.distTag !== distributionTag(entry.version) ||
			typeof entry.file !== "string" ||
			!new RegExp(`^${target.scope}/[a-zA-Z0-9_.+-]+\\.tgz$`).test(entry.file)
		)
			throw new Error("Artifact package identity mismatch");
		const path = join(directory, entry.file);
		if (!lstatSync(path).isFile() || !lstatSync(join(directory, target.scope)).isDirectory())
			throw new Error("Invalid artifact file");
		const bytes = readFileSync(path);
		if (integrity(bytes) !== entry.integrity) throw new Error("Artifact integrity mismatch");
		const pkg = inspectArchive(bytes, target, {
			internalVersions: manifest.internalVersions,
			expectedVersion: entry.version,
		});
		const dependencies = Object.fromEntries(
			Object.entries({
				...pkg.dependencies,
				...pkg.peerDependencies,
				...pkg.optionalDependencies,
			}).filter(([name]) => name.startsWith("@oidfed/")),
		);
		if (JSON.stringify(dependencies) !== JSON.stringify(entry.dependencies))
			throw new Error("Artifact dependencies mismatch");
		const notes = join(directory, `${target.scope}.md`);
		if (!lstatSync(notes).isFile() || sha256(readFileSync(notes)) !== entry.notesSha256)
			throw new Error("Release notes integrity mismatch");
	}
	return manifest;
}
