/** Entrypoints for the read-only verifier, OIDC publisher, and GitHub release completion job. */

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getTargets, parseTag, REPOSITORY, version, WORKFLOW } from "./catalog.mjs";
import { createArtifacts, loadArtifacts, validSha } from "./artifacts.mjs";
import { buildBody, extractSectionFromText } from "../extract-changelog.mjs";
import { previousTagFor } from "../release.mjs";
import {
	appendSummary,
	checkTags,
	completeRecords,
	github,
	publishRecords,
	requireMainCommit,
	selectedRecords,
	verifyOrigin,
	waitForSourceCi,
} from "./services.mjs";

function output(key, value) {
	if (!process.env.GITHUB_OUTPUT) throw new Error("Missing GitHub output file");
	appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

function environment() {
	if (process.env.GITHUB_REPOSITORY !== REPOSITORY)
		throw new Error("Releases must run in the upstream repository");
	const event = process.env.GITHUB_EVENT_NAME;
	if (event === "workflow_dispatch" && process.env.GITHUB_REF !== "refs/heads/main")
		throw new Error("Dispatch releases from main");
	if (!["workflow_dispatch", "push"].includes(event)) throw new Error("Unsupported release event");
	const tag = event === "push" ? parseTag(process.env.GITHUB_REF_NAME) : undefined;
	return {
		tag,
		scope: tag?.scope ?? process.env.RELEASE_SCOPE ?? "",
		directory: resolve(
			process.env.RELEASE_BUNDLE ?? `${process.env.RUNNER_TEMP ?? "."}/release-bundle`,
		),
	};
}

function checkCommittedVersions(records, sha) {
	if (!validSha(sha)) throw new Error("Invalid source SHA");
	for (const record of records) {
		const manifest = JSON.parse(
			execFileSync("git", ["show", `${sha}:${record.dir}/package.json`], { encoding: "utf8" }),
		);
		if (manifest.name !== record.name || (record.version && manifest.version !== record.version))
			throw new Error("Source package version mismatch");
		version(manifest.version);
		const notes = execFileSync("git", ["show", `${sha}:${record.dir}/CHANGELOG.md`], {
			encoding: "utf8",
		});
		if (!extractSectionFromText(notes, manifest.version))
			throw new Error(`Missing committed release notes for ${record.name}@${manifest.version}`);
	}
}

export async function main(command) {
	const { tag, scope, directory } = environment();
	if (command === "source") {
		const resume = process.env.RESUME_RUN_ID;
		let sha;
		let origin = process.env.GITHUB_RUN_ID;
		if (resume) {
			if (!/^[1-9]\d*$/.test(resume)) throw new Error("Invalid release run ID");
			const run = await github(`repos/${REPOSITORY}/actions/runs/${resume}`);
			if (run.path !== WORKFLOW || run.head_repository?.full_name !== REPOSITORY)
				throw new Error("Resume run belongs to another workflow or repository");
			const originTag = run.head_branch === "main" ? undefined : parseTag(run.head_branch);
			await verifyOrigin({
				runId: resume,
				workflowSha: run.head_sha,
				selected: originTag ? [originTag.scope] : [],
				packages: originTag ? [originTag] : [],
			});
			execFileSync(
				"gh",
				[
					"run",
					"download",
					resume,
					"--repo",
					REPOSITORY,
					"--name",
					"release-bundle",
					"--dir",
					directory,
				],
				{ stdio: "inherit" },
			);
			const manifest = loadArtifacts(directory);
			if (manifest.runId === resume && run.head_sha !== manifest.workflowSha)
				throw new Error("Resume workflow source mismatch");
			await verifyOrigin(manifest);
			sha = manifest.sourceSha;
			origin = manifest.runId;
			checkCommittedVersions(
				selectedRecords(manifest).map((r) => ({ ...getTargets(r.scope)[0], ...r })),
				sha,
			);
			await checkTags(selectedRecords(manifest), sha);
		} else {
			getTargets(scope);
			sha = tag ? process.env.GITHUB_SHA : process.env.SOURCE_SHA;
			checkCommittedVersions(tag ? [tag] : getTargets(scope), sha);
		}
		requireMainCommit(sha);
		await waitForSourceCi(sha);
		output("source_sha", sha);
		output("origin_run_id", origin);
		return;
	}
	if (command === "package") {
		const manifest = createArtifacts({
			directory,
			scope,
			sourceSha: process.env.SOURCE_SHA,
			workflowSha: process.env.GITHUB_SHA,
			runId: process.env.GITHUB_RUN_ID,
			notes(target, value) {
				const text = buildBody(
					target.scope,
					value,
					(path) => extractSectionFromText(readFileSync(path, "utf8"), value),
					previousTagFor(target.scope, value),
				);
				if (typeof text !== "string") throw new Error(text.error);
				return text;
			},
		});
		if (tag && manifest.packages.find((r) => r.scope === tag.scope).version !== tag.version)
			throw new Error("Tag version mismatch");
		await checkTags(selectedRecords(manifest), manifest.sourceSha);
		return;
	}
	const manifest = loadArtifacts(directory, {
		sourceSha: process.env.SOURCE_SHA,
		runId: process.env.ORIGIN_RUN_ID,
	});
	if (!process.env.RESUME_RUN_ID) {
		const expectedSelection = getTargets(scope).map((target) => target.scope);
		if (
			JSON.stringify(manifest.selected) !== JSON.stringify(expectedSelection) ||
			(tag &&
				manifest.packages.find((record) => record.scope === tag.scope).version !== tag.version)
		)
			throw new Error("Artifact selection differs from the release request");
	}
	await verifyOrigin(manifest);
	requireMainCommit(manifest.sourceSha);
	const records = selectedRecords(manifest);
	await checkTags(records, manifest.sourceSha);
	if (command === "publish") {
		await publishRecords(records, directory, {
			report: (rows) => appendSummary(process.env.GITHUB_STEP_SUMMARY, rows),
		});
	} else if (command === "complete") {
		await completeRecords(records, manifest.sourceSha, directory);
		appendSummary(
			process.env.GITHUB_STEP_SUMMARY,
			records.map((r) => ({ package: r.name, version: r.version, status: `released: ${r.tag}` })),
		);
	} else throw new Error("Choose source, package, publish, or complete");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	try {
		await main(process.argv[2]);
	} catch (error) {
		console.error(error.message);
		process.exitCode = 1;
	}
}
