/** GitHub and npm operations used by release jobs; failures remain distinct from missing data. */

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import semver from "semver";
import { NPM_VERSION, REPOSITORY, TARGETS, WORKFLOW, publicationOrder } from "./catalog.mjs";
import { validSha } from "./artifacts.mjs";

export class MissingResource extends Error {}

export function github(endpoint, { method = "GET", body } = {}) {
	if (!endpoint.startsWith(`repos/${REPOSITORY}/`))
		throw new Error("GitHub request outside release repository");
	try {
		const args = ["api", endpoint, "--method", method];
		if (body !== undefined) args.push("--input", "-");
		const output = execFileSync("gh", args, {
			encoding: "utf8",
			input: body === undefined ? undefined : JSON.stringify(body),
			stdio: ["pipe", "pipe", "pipe"],
		});
		return output.trim() ? JSON.parse(output) : undefined;
	} catch (error) {
		if (error.stderr?.toString().includes("(HTTP 404)")) throw new MissingResource(endpoint);
		throw new Error(`GitHub ${method} request failed: ${endpoint}`, { cause: error });
	}
}

export async function pages(api, endpoint, field) {
	const items = [];
	for (let page = 1; page <= 100; page++) {
		const data = await api(
			`${endpoint}${endpoint.includes("?") ? "&" : "?"}per_page=100&page=${page}`,
		);
		const entries = field ? data[field] : data;
		if (!Array.isArray(entries)) throw new Error("Invalid GitHub list response");
		items.push(...entries);
		if (entries.length < 100) return items;
	}
	throw new Error("GitHub pagination limit exceeded");
}

const REQUIRED = {
	"ci.yml": [
		"Commitlint",
		"Lint",
		"Scripts (unit)",
		"Packages & tools (typecheck)",
		"Tools (Vitest)",
		"Node",
		"Bun",
		"Deno",
		"workerd",
		"Electron",
		"Browser",
		"Coverage (TAP Node)",
		"E2E Tests",
	],
	"security.yml": [
		"Scoped source, dependencies, and artifacts",
		"CodeQL security-extended (six packages)",
	],
};

/** Keep missing job names distinct from jobs that are still running or queued. */
async function sourceCiStatus(sha, api) {
	const pending = [];
	const missing = [];
	for (const [workflow, required] of Object.entries(REQUIRED)) {
		const runs = await pages(
			api,
			`repos/${REPOSITORY}/actions/workflows/${workflow}/runs?head_sha=${sha}`,
			"workflow_runs",
		);
		const run = runs
			.filter(
				(r) =>
					r.head_sha === sha &&
					r.head_branch === "main" &&
					r.head_repository?.full_name === REPOSITORY &&
					["push", "workflow_dispatch"].includes(r.event),
			)
			.sort((a, b) => b.id - a.id)[0];
		if (!run)
			throw new Error(
				`Missing ${workflow} checks for ${sha}; run that workflow for the source commit`,
			);
		const jobs = await pages(
			api,
			`repos/${REPOSITORY}/actions/runs/${run.id}/jobs?filter=all`,
			"jobs",
		);
		const missingInRun = [];
		for (const name of required) {
			const job = jobs.filter((j) => j.name === name).sort((a, b) => b.id - a.id)[0];
			const label = `${workflow} run ${run.id}: ${name}`;
			if (!job) {
				missing.push(label);
				missingInRun.push(name);
			} else if (job.status !== "completed") pending.push(label);
			else if (job.conclusion !== "success")
				throw new Error(`Release blocked by ${label}: ${job.conclusion}`);
		}
		if (run.status === "completed" && missingInRun.length)
			throw new Error(
				`Missing required CI jobs in ${workflow} run ${run.id}: ${missingInRun.join(", ")}`,
			);
	}
	return { complete: pending.length === 0 && missing.length === 0, pending, missing };
}

/** Only origin/main workflow runs for this exact commit can authorize a release. */
export async function checkSourceCi(sha, api = github) {
	return (await sourceCiStatus(sha, api)).complete;
}

export async function waitForSourceCi(
	sha,
	{ api = github, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 40 } = {},
) {
	let status;
	for (let attempt = 0; attempt < attempts; attempt++) {
		status = await sourceCiStatus(sha, api);
		if (status.complete) return;
		if (attempt + 1 < attempts) {
			console.log("Waiting for source CI checks");
			await sleep(30_000);
		}
	}
	const details = [
		status?.missing.length ? `Missing jobs: ${status.missing.join("; ")}` : "",
		status?.pending.length ? `Pending jobs: ${status.pending.join("; ")}` : "",
	]
		.filter(Boolean)
		.join(". ");
	throw new Error(`Source CI checks did not complete after ${attempts} checks. ${details}`);
}

export function requireMainCommit(sha, execute = execFileSync) {
	if (!validSha(sha)) throw new Error("Invalid source SHA");
	execute("git", ["fetch", "--no-tags", "origin", "main"], { stdio: ["ignore", "ignore", "pipe"] });
	execute("git", ["merge-base", "--is-ancestor", sha, "refs/remotes/origin/main"], {
		stdio: ["ignore", "ignore", "pipe"],
	});
}

export async function tagCommit(tag, api = github) {
	let ref;
	try {
		ref = await api(`repos/${REPOSITORY}/git/ref/tags/${tag}`);
	} catch (error) {
		if (error instanceof MissingResource) return undefined;
		throw error;
	}
	let object = ref.object;
	for (let depth = 0; object?.type === "tag" && depth < 5; depth++)
		object = (await api(`repos/${REPOSITORY}/git/tags/${object.sha}`)).object;
	if (object?.type !== "commit" || !validSha(object.sha))
		throw new Error(`Invalid tag object: ${tag}`);
	return object.sha;
}

export async function checkTags(records, sourceSha, api = github) {
	for (const record of records) {
		const existing = await tagCommit(record.tag, api);
		if (existing !== undefined && existing !== sourceSha)
			throw new Error(`Tag ${record.tag} already points to another commit`);
	}
}

/** A resumable run must have successfully uploaded artifacts through this repository's verifier. */
export async function verifyOrigin(manifest, api = github) {
	const run = await api(`repos/${REPOSITORY}/actions/runs/${manifest.runId}`);
	if (
		run.head_repository?.full_name !== REPOSITORY ||
		run.path !== WORKFLOW ||
		run.head_sha !== manifest.workflowSha ||
		!["push", "workflow_dispatch"].includes(run.event) ||
		(run.head_branch !== "main" &&
			!manifest.selected.some(
				(scope) => run.head_branch === manifest.packages.find((p) => p.scope === scope).tag,
			))
	)
		throw new Error("Saved release workflow identity mismatch");
	const jobs = await pages(
		api,
		`repos/${REPOSITORY}/actions/runs/${manifest.runId}/jobs?filter=all`,
		"jobs",
	);
	const verifier = jobs
		.filter((job) => job.name === "Verify and package")
		.sort((a, b) => b.id - a.id)[0];
	if (verifier?.conclusion !== "success")
		throw new Error("Saved release verification did not succeed");
}

export async function registryJson(
	path,
	{ request = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {},
) {
	for (let attempt = 0; attempt < 5; attempt++) {
		let response;
		try {
			response = await request(`https://registry.npmjs.org/${path}`, {
				signal: AbortSignal.timeout(20_000),
				redirect: "error",
			});
		} catch (error) {
			if (attempt === 4) throw new Error("npm registry could not be reached", { cause: error });
		}
		if (response?.status === 404) return undefined;
		if (response?.ok) return response.json();
		if (response && response.status !== 429 && response.status < 500)
			throw new Error(`npm registry returned ${response.status}`);
		if (attempt === 4)
			throw new Error(`npm registry unavailable (${response?.status ?? "transport"})`);
		await sleep(1000 * 2 ** attempt);
	}
}

export const registryVersion = (record, read = registryJson) =>
	read(`${encodeURIComponent(record.name)}/${encodeURIComponent(record.version)}`);

function matchesPublished(record, data) {
	if (
		data.name !== record.name ||
		data.version !== record.version ||
		data.dist?.integrity !== record.integrity
	)
		throw new Error(`Published integrity mismatch for ${record.name}@${record.version}`);
}

export async function preflight(records, read = registryJson) {
	const ordered = publicationOrder(records);
	const selected = new Map(records.map((r) => [r.name, r]));
	const existing = new Set();
	for (const record of ordered) {
		const published = await registryVersion(record, read);
		if (published) {
			matchesPublished(record, published);
			existing.add(record.name);
		} else if (record.distTag === "latest") {
			const latest = await read(`${encodeURIComponent(record.name)}/latest`);
			if (latest && (!semver.valid(latest.version) || semver.gt(latest.version, record.version)))
				throw new Error(`Publishing ${record.name}@${record.version} would move latest backward`);
		}
		for (const [name, range] of Object.entries(record.dependencies)) {
			if (selected.has(name)) continue;
			if (!TARGETS.some((p) => p.name === name))
				throw new Error("Unknown internal release dependency");
			const metadata = await read(encodeURIComponent(name));
			if (
				!metadata ||
				!Object.keys(metadata.versions ?? {}).some((v) => semver.satisfies(v, range))
			)
				throw new Error(`${record.name} requires an unpublished dependency: ${name}@${range}`);
		}
	}
	return { ordered, existing };
}

export async function confirmPublished(
	record,
	{ read = registryJson, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {},
) {
	for (let attempt = 0; attempt < 5; attempt++) {
		const data = await registryVersion(record, read);
		if (data) {
			matchesPublished(record, data);
			return;
		}
		if (attempt < 4) await sleep(2000 * 2 ** attempt);
	}
	throw new Error(`npm has not confirmed ${record.name}@${record.version}`);
}

/** Do not retry an uncertain publish: confirm it in npm, or leave recovery to the saved bundle. */
export async function publishRecords(
	records,
	directory,
	{ read = registryJson, execute = execFileSync, sleep, report = () => {} } = {},
) {
	const ordered = publicationOrder(records);
	const summary = [];
	try {
		const { existing } = await preflight(ordered, read);
		for (const record of ordered) {
			if (existing.has(record.name)) {
				summary.push({ package: record.name, version: record.version, status: "already-present" });
				continue;
			}
			let commandError;
			try {
				execute(
					"pnpm",
					[
						"--package",
						`npm@${NPM_VERSION}`,
						"dlx",
						"npm",
						"publish",
						join(directory, record.file),
						"--ignore-scripts",
						"--provenance",
						"--access",
						"public",
						"--tag",
						record.distTag,
					],
					{ stdio: "inherit" },
				);
			} catch (error) {
				commandError = error;
			}
			try {
				await confirmPublished(record, { read, sleep });
			} catch (error) {
				summary.push({ package: record.name, version: record.version, status: "failed" });
				throw new Error(
					`Publication failed for ${record.name}; resume with the saved release run`,
					{ cause: commandError ?? error },
				);
			}
			summary.push({ package: record.name, version: record.version, status: "published" });
		}
		return summary;
	} finally {
		for (const record of ordered)
			if (!summary.some((r) => r.package === record.name))
				summary.push({ package: record.name, version: record.version, status: "incomplete" });
		report(summary);
	}
}

async function findRelease(tag, api) {
	try {
		return await api(`repos/${REPOSITORY}/releases/tags/${tag}`);
	} catch (error) {
		if (!(error instanceof MissingResource)) throw error;
	}
	// The tag endpoint returns published releases; authenticated listings also include drafts.
	const releases = await pages(api, `repos/${REPOSITORY}/releases`);
	const matches = releases.filter((release) => release.tag_name === tag);
	if (matches.length > 1) throw new Error(`Multiple GitHub releases for ${tag}`);
	return matches[0];
}

export async function completeRecords(
	records,
	sourceSha,
	directory,
	{ api = github, read = registryJson, execute = execFileSync, sleep } = {},
) {
	for (const record of records) await confirmPublished(record, { read, sleep });
	await checkTags(records, sourceSha, api);
	for (const record of records) {
		if (!(await tagCommit(record.tag, api))) {
			const tag = await api(`repos/${REPOSITORY}/git/tags`, {
				method: "POST",
				body: {
					tag: record.tag,
					message: `Release ${record.name} ${record.version}`,
					object: sourceSha,
					type: "commit",
				},
			});
			try {
				await api(`repos/${REPOSITORY}/git/refs`, {
					method: "POST",
					body: { ref: `refs/tags/${record.tag}`, sha: tag.sha },
				});
			} catch (error) {
				if ((await tagCommit(record.tag, api)) !== sourceSha) throw error;
			}
		}
		let release = await findRelease(record.tag, api);
		const body = readFileSync(join(directory, `${record.scope}.md`), "utf8");
		if (!release) {
			try {
				release = await api(`repos/${REPOSITORY}/releases`, {
					method: "POST",
					body: {
						tag_name: record.tag,
						target_commitish: sourceSha,
						name: `${record.name} ${record.version}`,
						body,
						draft: true,
						prerelease: record.distTag !== "latest",
					},
				});
			} catch (error) {
				// A concurrent completion or a lost response can leave the release already created.
				release = await findRelease(record.tag, api);
				if (!release) throw error;
			}
		}
		const checksum = join(directory, `${record.scope}-${record.version}.sha512`);
		const hex = Buffer.from(record.integrity.slice("sha512-".length), "base64").toString("hex");
		writeFileSync(checksum, `${hex}  ${record.file.split("/").at(-1)}\n`);
		execute("gh", ["release", "upload", record.tag, checksum, "--repo", REPOSITORY, "--clobber"], {
			stdio: "inherit",
		});
		if (release.draft)
			await api(`repos/${REPOSITORY}/releases/${release.id}`, {
				method: "PATCH",
				// Independent package versions do not define one repository-wide latest release.
				body: { body, draft: false, prerelease: record.distTag !== "latest", make_latest: "false" },
			});
	}
}

export function appendSummary(path, rows) {
	if (path)
		appendFileSync(
			path,
			`\n| Package | Version | Status |\n|---|---|---|\n${rows.map((r) => `| ${r.package} | ${r.version} | ${r.status} |`).join("\n")}\n`,
		);
}

export function selectedRecords(manifest) {
	return manifest.packages.filter((record) => manifest.selected.includes(record.scope));
}
