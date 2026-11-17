/** Validate workflow trust, permissions and idempotent GitHub release completion. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parse } from "yaml";
import { REPOSITORY, WORKFLOW } from "./release/catalog.mjs";
import { bundle, registry, SHA } from "./release/test-fixtures.mjs";
import {
	checkSourceCi,
	waitForSourceCi,
	verifyOrigin,
	MissingResource,
	completeRecords,
	checkTags,
} from "./release/services.mjs";

const ci = parse(readFileSync(".github/workflows/ci.yml", "utf8"));
const security = parse(readFileSync(".github/workflows/security.yml", "utf8"));
function ciApi({ failure, pending = false, foreign = false, missing } = {}) {
	const required = [
		...Object.values(ci.jobs)
			.map((j) => j.name)
			.filter((name) => !name.startsWith("Apps ")),
		"Scoped source, dependencies, and artifacts",
		"CodeQL security-extended (five packages)",
	];
	return async (path) =>
		path.includes("/jobs?")
			? {
					jobs: required
						.filter((name) => name !== missing)
						.map((name, id) => ({
							id,
							name,
							status: pending ? "in_progress" : "completed",
							conclusion: name === failure ? "failure" : "success",
						})),
				}
			: {
					workflow_runs: [
						{
							id: 1,
							status: pending ? "in_progress" : "completed",
							head_sha: SHA,
							head_branch: "main",
							head_repository: { full_name: foreign ? "other/repo" : REPOSITORY },
							event: "push",
						},
					],
				};
}
test("release CI gate is exact-commit and rejects failed, foreign or incomplete checks", async () => {
	assert.equal(await checkSourceCi(SHA, ciApi()), true);
	assert.equal(await checkSourceCi(SHA, ciApi({ pending: true })), false);
	await assert.rejects(
		checkSourceCi(SHA, ciApi({ failure: "CodeQL security-extended (five packages)" })),
		/blocked/,
	);
	await assert.rejects(checkSourceCi(SHA, ciApi({ foreign: true })), /Missing/);
	await assert.rejects(
		waitForSourceCi(SHA, { api: ciApi({ pending: true }), attempts: 2, sleep: async () => {} }),
		/did not complete/,
	);
});

test("completed CI runs identify missing required jobs without waiting", async () => {
	const missing = "Scoped source, dependencies, and artifacts";
	await assert.rejects(
		waitForSourceCi(SHA, {
			api: ciApi({ missing }),
			sleep: async () => assert.fail("a completed run cannot add the missing job"),
		}),
		(error) => error.message.includes("security.yml run 1") && error.message.includes(missing),
	);
});

test("CI timeouts distinguish missing jobs from pending jobs and allow jobs to appear", async () => {
	const missing = "Scoped source, dependencies, and artifacts";
	await assert.rejects(
		waitForSourceCi(SHA, {
			api: ciApi({ pending: true, missing }),
			attempts: 2,
			sleep: async () => {},
		}),
		(error) =>
			error.message.includes(`Missing jobs: security.yml run 1: ${missing}`) &&
			error.message.includes("Pending jobs:") &&
			error.message.includes("ci.yml run 1: Node"),
	);
	let ready = false;
	await waitForSourceCi(SHA, {
		api: (path) => ciApi(ready ? {} : { pending: true, missing })(path),
		attempts: 2,
		sleep: async () => {
			ready = true;
		},
	});
});

test("CLI release preparation triggers the required security workflow", () => {
	for (const event of ["push", "pull_request"])
		assert.ok(security.on[event].paths.includes("tools/cli/**"), event);
});

test("the scoped security job runs rule fixtures and source checks before release acceptance", () => {
	const commands = security.jobs.checks.steps.flatMap((step) => step.run ? [step.run] : []);
	assert.ok(commands.includes("pnpm security:test"));
	assert.ok(commands.includes("pnpm security:lint"));
	assert.ok(commands.indexOf("pnpm security:test") < commands.indexOf("pnpm security:lint"));
	assert.equal(Object.values(security.jobs).filter((job) => job.strategy?.matrix?.python).length, 0);
});

test("saved runs require the correct repository, workflow, workflow commit and completed verifier", async () => {
	const manifest = {
		runId: "123",
		workflowSha: SHA,
		selected: ["core"],
		packages: [{ scope: "core", tag: "core/v2.0.0" }],
	};
	const run = {
		head_repository: { full_name: REPOSITORY },
		path: WORKFLOW,
		head_sha: SHA,
		head_branch: "main",
		event: "workflow_dispatch",
	};
	const api = async (path) =>
		path.includes("/jobs?")
			? { jobs: [{ id: 1, name: "Verify and package", conclusion: "success" }] }
			: run;
	await verifyOrigin(manifest, api);
	for (const change of [
		{ path: "other.yml" },
		{ head_sha: "b".repeat(40) },
		{ head_repository: { full_name: "other/repo" } },
		{ head_branch: "unreviewed" },
		{ event: "pull_request" },
	])
		await assert.rejects(
			verifyOrigin(manifest, async (path) =>
				path.includes("/jobs?") ? api(path) : { ...run, ...change },
			),
			/identity/,
		);
	await assert.rejects(
		verifyOrigin(manifest, async (path) =>
			path.includes("/jobs?")
				? { jobs: [{ id: 2, name: "Verify and package", conclusion: "failure" }] }
				: run,
		),
		/did not succeed/,
	);
});

for (const uncertainCreate of [false, true])
	test(`release completion recovers drafts and conflicting tags (uncertain creation: ${uncertainCreate})`, async () => {
		const root = mkdtempSync(join(tmpdir(), "oidfed-complete-")),
			directory = join(root, "bundle");
		try {
			const manifest = bundle(directory, "core"),
				record = manifest.packages[0],
				remote = registry();
			remote.put(record);
			const refs = new Map(),
				objects = new Map(),
				releases = new Map(),
				calls = [];
			const prefix = `repos/${REPOSITORY}`;
			const api = async (path, options = {}) => {
				calls.push([path, options]);
				if (path.startsWith(`${prefix}/git/ref/tags/`)) {
					const ref = refs.get(path.slice(`${prefix}/git/ref/tags/`.length));
					if (!ref) throw new MissingResource("missing");
					return ref;
				}
				if (path === `${prefix}/git/tags`) {
					const sha = "b".repeat(40);
					objects.set(sha, { object: { type: "commit", sha: options.body.object } });
					return { sha };
				}
				if (path.startsWith(`${prefix}/git/tags/`)) return objects.get(path.split("/").at(-1));
				if (path === `${prefix}/git/refs`) {
					refs.set(options.body.ref.slice("refs/tags/".length), {
						object: { type: "tag", sha: options.body.sha },
					});
					return {};
				}
				if (path.startsWith(`${prefix}/releases/tags/`)) {
					const release = releases.get(record.tag);
					if (!release || release.draft) throw new MissingResource("missing");
					return release;
				}
				if (path.startsWith(`${prefix}/releases?`)) return [...releases.values()];
				if (path === `${prefix}/releases`) {
					assert.equal(releases.has(record.tag), false, "reuse the existing draft");
					const release = { id: 1, ...options.body };
					releases.set(record.tag, release);
					if (uncertainCreate) throw Error("response lost after creation");
					return release;
				}
				if (path === `${prefix}/releases/1`) {
					Object.assign(releases.get(record.tag), options.body);
					return releases.get(record.tag);
				}
				throw Error(`Unexpected request ${path}`);
			};
			let fail = true,
				uploads = 0;
			const execute = (command, args) => {
				assert.equal(command, "gh");
				assert.equal(args[2], record.tag);
				assert.match(readFileSync(args[3], "utf8"), /^[a-f0-9]{128}  core\.tgz\n$/);
				uploads++;
				if (fail) throw Error("upload interrupted");
			};
			await assert.rejects(
				completeRecords([record], SHA, directory, { api, read: remote.read, execute }),
				/interrupted/,
			);
			assert.equal(releases.get(record.tag).draft, true);
			fail = false;
			await completeRecords([record], SHA, directory, { api, read: remote.read, execute });
			assert.equal(releases.get(record.tag).draft, false);
			await completeRecords([record], SHA, directory, { api, read: remote.read, execute });
			assert.equal(calls.filter(([path]) => path === `${prefix}/releases`).length, 1);
			assert.equal(uploads, 3);
			refs.set(record.tag, { object: { type: "commit", sha: "c".repeat(40) } });
			await assert.rejects(checkTags([record], SHA, api), /another commit/);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

test("workflow preserves permission boundaries and only package-specific tag triggers", () => {
	const document = parse(readFileSync(".github/workflows/release.yml", "utf8"));
	assert.equal(
		document.on.push.tags.some((tag) => tag.startsWith("all/")),
		false,
	);
	assert.deepEqual(document.permissions, { contents: "read" });
	assert.equal(document.jobs.verify.permissions["id-token"], undefined);
	assert.equal(document.jobs.verify.permissions.contents, "read");
	assert.equal(document.jobs.publish.permissions["id-token"], "write");
	assert.equal(document.jobs.publish.permissions.contents, "read");
	assert.equal(document.jobs.complete.permissions["id-token"], undefined);
	assert.equal(document.jobs.complete.permissions.contents, "write");
	assert.equal(document.jobs.publish.concurrency.queue, "max");
	assert.equal(document.jobs.publish.concurrency["cancel-in-progress"], false);
	assert.equal(document.jobs.publish.environment, "npm");
	assert.equal(security.jobs.codeql.name, "CodeQL security-extended (five packages)");
});
