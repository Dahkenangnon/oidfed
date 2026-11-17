/** Exercise the publisher and recovery against an isolated registry; never publish real packages. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { bundle, registry } from "./release/test-fixtures.mjs";
import {
	publishRecords,
	preflight,
	registryJson,
	selectedRecords,
	confirmPublished,
} from "./release/services.mjs";

const noWait = async () => {};
test("batch publication orders dependencies, propagates failures and resumes identical archives", async () => {
	const root = mkdtempSync(join(tmpdir(), "oidfed-publish-")),
		directory = join(root, "bundle");
	try {
		const manifest = bundle(directory),
			records = selectedRecords(manifest),
			remote = registry();
		const calls = [],
			reports = [];
		let fail = true;
		const execute = (command, args) => {
			assert.equal(command, "pnpm");
			assert.ok(args.includes("npm@11.21.2"));
			assert.ok(args.includes("--ignore-scripts"));
			const path = args[args.indexOf("publish") + 1],
				record = records.find((r) => join(directory, r.file) === path);
			assert.ok(record, "the exact selected archive is published");
			calls.push(record.scope);
			if (record.scope === "authority" && fail) throw Error("network interrupted");
			remote.put(record);
		};
		await assert.rejects(
			publishRecords(records, directory, {
				read: remote.read,
				execute,
				sleep: noWait,
				report: (r) => reports.push(r),
			}),
			/Publication failed/,
		);
		assert.deepEqual(calls, ["core", "authority"]);
		assert.ok(reports[0].some((r) => r.status === "incomplete"));
		fail = false;
		calls.length = 0;
		const result = await publishRecords(records, directory, {
			read: remote.read,
			execute,
			sleep: noWait,
		});
		assert.equal(result.find((r) => r.package === "@oidfed/core").status, "already-present");
		assert.equal(calls.includes("core"), false);
		assert.equal(calls.length, 5);
		calls.length = 0;
		await publishRecords(records, directory, { read: remote.read, execute, sleep: noWait });
		assert.equal(calls.length, 0);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("preflight rejects mismatched published bytes, unavailable dependencies and latest downgrade", async () => {
	const root = mkdtempSync(join(tmpdir(), "oidfed-preflight-")),
		directory = join(root, "bundle");
	try {
		const manifest = bundle(directory),
			core = manifest.packages[0],
			authority = manifest.packages[1],
			remote = registry();
		remote.put({ ...core, integrity: "different" });
		await assert.rejects(preflight([core], remote.read), /integrity mismatch/);
		remote.data.clear();
		remote.data.set(`${encodeURIComponent(core.name)}/latest`, { version: "99.0.0" });
		await assert.rejects(preflight([core], remote.read), /latest backward/);
		remote.data.clear();
		await assert.rejects(preflight([authority], remote.read), /unpublished dependency/);
		remote.data.set(encodeURIComponent(core.name), { versions: { [core.version]: {} } });
		assert.equal((await preflight([authority], remote.read)).ordered.length, 1);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("uncertain publication is confirmed instead of blindly repeated", async () => {
	const record = {
		name: "@oidfed/core",
		scope: "core",
		version: "2.0.1",
		file: "core/core.tgz",
		integrity: "sha512-test",
		distTag: "latest",
		dependencies: {},
	};
	const remote = registry();
	let requests = 0;
	const result = await publishRecords([record], "/tmp/saved", {
		read: remote.read,
		sleep: noWait,
		execute() {
			requests++;
			remote.put(record);
			throw Error("connection closed after upload");
		},
	});
	assert.equal(requests, 1);
	assert.equal(result[0].status, "published");
});

test("a registry preflight failure reports all packages as incomplete without publishing", async () => {
	const record = { name: "@oidfed/core", version: "2.0.1", dependencies: {} };
	let summary;
	await assert.rejects(
		publishRecords([record], "/tmp/saved", {
			read: async () => {
				throw new Error("registry unavailable");
			},
			execute: () => assert.fail("must not publish after preflight failure"),
			report: (rows) => {
				summary = rows;
			},
		}),
		/registry unavailable/,
	);
	assert.deepEqual(summary, [
		{ package: record.name, version: record.version, status: "incomplete" },
	]);
});

test("registry outages are not treated as missing versions; propagation retries are bounded", async () => {
	let calls = 0;
	assert.equal(
		await registryJson("package", {
			request: async () => new Response("", { status: 404 }),
			sleep: noWait,
		}),
		undefined,
	);
	await assert.rejects(
		registryJson("package", {
			request: async () => {
				calls++;
				return new Response("", { status: 503 });
			},
			sleep: noWait,
		}),
		/unavailable/,
	);
	assert.equal(calls, 5);
	await assert.rejects(
		registryJson("package", {
			request: async () => new Response("", { status: 401 }),
			sleep: noWait,
		}),
		/401/,
	);
	calls = 0;
	await confirmPublished(
		{ name: "pkg", version: "1.0.0", integrity: "ok" },
		{
			read: async () =>
				++calls < 3 ? undefined : { name: "pkg", version: "1.0.0", dist: { integrity: "ok" } },
			sleep: noWait,
		},
	);
	assert.equal(calls, 3);
});
