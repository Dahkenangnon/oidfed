/** Harness regressions; these tests use no Docker or conformance suite deployment. */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fetch, Response } from "undici";
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { ConformanceApi, MAX_ENTRY_BYTES, readBody, type SuiteApi } from "./api.js";
import { execute, Session } from "./driver.js";
import { checkExport } from "./exports.js";
import {
	ApplicationOutcomeError,
	BASELINE,
	diagnostics,
	ENCRYPTED,
	ensureComplete,
	grade,
	HarnessError,
	instances,
	inventory,
	ModuleFailure,
	moduleVariant,
	type PlanInfo,
	type Report,
	recordError,
	rpOutcome,
} from "./policy.js";
import { command, ROOT, validateOptions, withEnvironment } from "./run.js";

const temporary: string[] = [];
async function temp(): Promise<string> {
	const path = await mkdtemp(join(tmpdir(), "oidfed-harness-"));
	temporary.push(path);
	return path;
}
afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	for (const path of temporary.splice(0)) await rm(path, { recursive: true, force: true });
});

function plan(): PlanInfo {
	return {
		id: "plan",
		modules: BASELINE.plans.deployed.modules.map((x) => ({ testModule: x.name, variant: null })),
	};
}
function apiMock(): SuiteApi {
	return {
		wait: vi.fn().mockResolvedValue(undefined),
		info: vi.fn().mockResolvedValue({ status: "CONFIGURED" }),
		logs: vi.fn().mockResolvedValue([{ result: "SUCCESS" }]),
		start: vi.fn().mockResolvedValue(undefined),
		cancel: vi.fn().mockResolvedValue(undefined),
	};
}

// Small stored ZIP fixtures keep archive-writing dependencies out of the harness.
function zip(entries: { name: string; text: string; declaredSize?: number }[]): Buffer {
	const files: Buffer[] = [],
		directory: Buffer[] = [];
	let offset = 0;
	for (const entry of entries) {
		const name = Buffer.from(entry.name),
			data = Buffer.from(entry.text),
			size = entry.declaredSize ?? data.length;
		let crc = 0xffffffff;
		for (const byte of data) {
			crc ^= byte;
			for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
		}
		crc = (crc ^ 0xffffffff) >>> 0;
		const local = Buffer.alloc(30);
		local.writeUInt32LE(0x04034b50);
		local.writeUInt16LE(20, 4);
		local.writeUInt32LE(crc, 14);
		local.writeUInt32LE(size, 18);
		local.writeUInt32LE(size, 22);
		local.writeUInt16LE(name.length, 26);
		const central = Buffer.alloc(46);
		central.writeUInt32LE(0x02014b50);
		central.writeUInt16LE(20, 4);
		central.writeUInt16LE(20, 6);
		central.writeUInt32LE(crc, 16);
		central.writeUInt32LE(size, 20);
		central.writeUInt32LE(size, 24);
		central.writeUInt16LE(name.length, 28);
		central.writeUInt32LE(offset, 42);
		files.push(local, name, data);
		directory.push(central, name);
		offset += local.length + name.length + data.length;
	}
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50);
	end.writeUInt16LE(entries.length, 8);
	end.writeUInt16LE(entries.length, 10);
	end.writeUInt32LE(Buffer.concat(directory).length, 12);
	end.writeUInt32LE(offset, 16);
	return Buffer.concat([...files, ...directory, end]);
}
const exported = (id = "abc", result = "PASSED") =>
	JSON.stringify({ testInfo: { id, status: "FINISHED", result } });

describe("result policy", () => {
	test("full includes every plan exactly once", () => {
		expect([...BASELINE.profiles.full].sort()).toEqual(Object.keys(BASELINE.plans).sort());
		expect(new Set(BASELINE.profiles.full).size).toBe(BASELINE.profiles.full.length);
		for (const role of ["deployed", "rp", "op"] as const)
			expect(BASELINE.profiles[role]).toEqual([role]);
	});
	test("only a finished pass is accepted", () => {
		for (const status of ["CONFIGURED", "WAITING", "RUNNING", "INTERRUPTED", "FINISHED"])
			for (const result of ["PASSED", "FAILED", "WARNING", "REVIEW", "UNKNOWN", "SKIPPED"])
				expect(grade("ordinary", "op", { status, result }, [{ result: "SUCCESS" }])).toBe(
					status === "FINISHED" && result === "PASSED",
				);
		expect(grade("ordinary", "op", { status: "FINISHED" }, [{ result: "SUCCESS" }])).toBe(false);
	});
	test("missing logs and failed or unreviewed conditions reject a pass", () => {
		for (const logs of [
			[],
			[{ result: "FAILURE", src: "BROWSER" }],
			[{ result: "WARNING" }],
			[{ result: "REVIEW" }],
		])
			expect(grade("ordinary", "op", { status: "FINISHED", result: "PASSED" }, logs)).toBe(false);
	});
	test("optional skips are limited to their capability and target", () => {
		const info = { status: "FINISHED", result: "SKIPPED" };
		const encrypted = [
			{
				result: "SKIPPED",
				msg: "The test was skipped: The server does not support encrypted request objects",
			},
		];
		expect(grade(ENCRYPTED, "op", info, encrypted)).toBe(true);
		expect(grade("another-module", "op", info, encrypted)).toBe(false);
		expect(grade(ENCRYPTED, "op", info, [{ result: "SKIPPED", msg: "Other failure" }])).toBe(false);
		const name = "openid-federation-ensure-fetch-with-invalid-sub-fails";
		const logs = [
			{
				result: "SKIPPED",
				msg: "The test was skipped: Entity metadata does not contain a federation_fetch_endpoint.",
			},
		];
		expect(grade(name, "leaf", info, logs)).toBe(true);
		expect(grade(name, "ia", info, logs)).toBe(false);
	});
	test("missing, added, and duplicated plan modules fail inventory", () => {
		inventory(plan(), "deployed");
		const first = plan().modules[0];
		if (!first) throw new Error("Expected a nonempty baseline");
		for (const modules of [
			plan().modules.slice(1),
			[...plan().modules, { testModule: "unexpected" }],
			[...plan().modules, first],
			[],
		])
			expect(() => inventory({ id: "plan", modules }, "deployed")).toThrow(
				"plan_inventory_mismatch",
			);
	});
	test("variant drift and hidden reruns fail", () => {
		const changed = plan();
		const first = changed.modules[0];
		if (!first) throw new Error("Expected a nonempty baseline");
		first.variant = { server_metadata: "static" };
		expect(() => inventory(changed, "deployed")).toThrow("module_variant_mismatch");
		moduleVariant({ variant: BASELINE.variants });
		expect(() => moduleVariant({ variant: {} })).toThrow();
		instances(
			{ id: "p", modules: [{ testModule: "module", instances: ["one"] }] },
			new Map([["module", "one"]]),
		);
		for (const ids of [[], ["one", "two"], ["other"]])
			expect(() =>
				instances(
					{ id: "p", modules: [{ testModule: "module", instances: ids }] },
					new Map([["module", "one"]]),
				),
			).toThrow("module_execution_mismatch");
	});
	test("RP acceptance is independent of suite module success", () => {
		const happy = "openid-federation-client-test",
			invalid = "openid-federation-client-invalid-aud-in-id-token";
		rpOutcome(happy, 200, { accepted: true, stage: "protocol" });
		rpOutcome(invalid, 400, { accepted: false, stage: "protocol" });
		expect(() => rpOutcome(happy, 200, { accepted: true, stage: ["protocol"] })).toThrow(
			ApplicationOutcomeError,
		);
		for (const [name, status, body] of [
			[invalid, 200, { accepted: true, stage: "protocol" }],
			[happy, 400, { accepted: false, stage: "federation" }],
			[invalid, 400, { accepted: false, stage: "federation" }],
		] as const)
			expect(() => rpOutcome(name, status, body)).toThrow(ApplicationOutcomeError);
	});
	test("raw data does not reach public diagnostics", () => {
		const data = JSON.stringify(
			diagnostics([
				{
					src: "ValidateSignature",
					result: "FAILURE",
					...{ msg: "secret", private_key: "secret" },
				},
				{ src: "key: secret", result: "WARNING" },
			]),
		);
		expect(data).not.toContain("secret");
		expect(data).toContain("ValidateSignature");
		const report: Report = { revision: "pin", profile: "rp", modules: [], passed: false };
		recordError(report, new Error("private assertion"));
		expect(JSON.stringify(report)).not.toContain("private assertion");
	});
	test("a zero exit code cannot substitute for a complete profile report", () => {
		const report: Report = {
			revision: BASELINE.revision,
			profile: "deployed",
			passed: true,
			modules: ["ta", "ia", "leaf"].flatMap((target) =>
				BASELINE.plans.deployed.modules.map((module) => ({
					name: module.name,
					target,
					status: "FINISHED",
					result: "PASSED",
					accepted: true,
					diagnostics: [],
				})),
			),
		};
		ensureComplete(report, "deployed");
		for (const changed of [
			undefined,
			{},
			{ ...report, passed: false },
			{ ...report, modules: report.modules.slice(1) },
			{ ...report, modules: [...report.modules, report.modules[0]] },
			{ ...report, profile: "rp" },
			{ ...report, modules: report.modules.map((x) => ({ ...x, accepted: false })) },
		])
			expect(() => ensureComplete(changed, "deployed")).toThrow("incomplete_report");
	});
});

describe("export verification", () => {
	test("export must match every instance and its result", async () => {
		const file = join(await temp(), "export.zip");
		await writeFile(file, zip([{ name: "test-log.json", text: exported() }]));
		await checkExport(file, new Map([["abc", ["FINISHED", "PASSED"]]]));
		for (const expected of [
			new Map(),
			new Map([["abc", ["FINISHED", "FAILED"]]]),
			new Map([
				["abc", ["FINISHED", "PASSED"]],
				["missing", ["FINISHED", "PASSED"]],
			]),
		])
			await expect(checkExport(file, expected as Map<string, [string, string]>)).rejects.toThrow(
				"export_result_mismatch",
			);
	});
	test("duplicate exported instances fail", async () => {
		const file = join(await temp(), "export.zip");
		await writeFile(
			file,
			zip([
				{ name: "one.json", text: exported() },
				{ name: "two.json", text: exported() },
			]),
		);
		await expect(checkExport(file, new Map([["abc", ["FINISHED", "PASSED"]]]))).rejects.toThrow(
			"duplicate_export_instance",
		);
	});
	test("a CRC mismatch rejects otherwise matching JSON", async () => {
		const bytes = zip([{ name: "log.json", text: exported() }]);
		const central = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
		bytes.writeUInt32LE(0, central + 16);
		const file = join(await temp(), "export.zip");
		await writeFile(file, bytes);
		await expect(checkExport(file, new Map([["abc", ["FINISHED", "PASSED"]]]))).rejects.toThrow(
			"invalid_export",
		);
	});
	test("malformed, truncated, oversized, and unsafe archives fail", async () => {
		const file = join(await temp(), "export.zip");
		for (const bytes of [
			Buffer.from("not a ZIP"),
			zip([{ name: "log.json", text: "{" }]),
			zip([{ name: "log.json", text: exported(), declaredSize: MAX_ENTRY_BYTES + 1 }]),
			zip([{ name: "../escape.json", text: exported() }]),
			zip([{ name: "log.json", text: exported() }]).subarray(0, 40),
		]) {
			await writeFile(file, bytes);
			await expect(checkExport(file, new Map())).rejects.toThrow(HarnessError);
		}
	});
});

describe("lifecycle", () => {
	test("launcher help runs without Docker or Python", async () => {
		const { stdout } = await promisify(execFile)(
			process.execPath,
			[
				join(ROOT, "node_modules/tsx/dist/cli.mjs"),
				join(ROOT, "tests/conformance/run.ts"),
				"--help",
			],
			{ env: { ...process.env, PATH: "" } },
		);
		expect(stdout).toContain("--profile deployed|rp|op|full");
		expect(stdout).toContain("--keep-private");
	});
	test("aborted child processes stop before command completion", async () => {
		const controller = new AbortController();
		const running = command([process.execPath, "-e", "setInterval(() => {}, 1000)"], {
			quiet: true,
			signal: controller.signal,
		});
		controller.abort();
		await expect(running).rejects.toThrow("command_failed");
	});
	test("failure removes Compose resources and private state", async () => {
		const state = await temp(),
			run = vi.fn().mockResolvedValue(undefined);
		await expect(
			withEnvironment(
				["docker", "compose"],
				{},
				state,
				false,
				async () => {
					throw new Error("fixture failed");
				},
				run,
			),
		).rejects.toThrow("fixture failed");
		await expect(stat(state)).rejects.toMatchObject({ code: "ENOENT" });
		expect(run.mock.calls[0]?.[0]).toContain("--volumes");
	});
	test("private state is removed even if Docker cleanup throws", async () => {
		const state = await temp();
		await expect(
			withEnvironment(
				["docker", "compose"],
				{},
				state,
				false,
				async () => {},
				vi.fn().mockRejectedValue(new Error("Docker unavailable")),
			),
		).rejects.toThrow("Docker unavailable");
		await expect(stat(state)).rejects.toMatchObject({ code: "ENOENT" });
	});
	test("private retention is opt-in and forbidden in CI", async () => {
		const state = await temp();
		await writeFile(join(state, "diagnostic"), "private");
		await withEnvironment(
			["docker", "compose"],
			{},
			state,
			true,
			async () => {},
			vi.fn().mockResolvedValue(undefined),
		);
		expect(await readFile(join(state, "diagnostic"), "utf8")).toBe("private");
		vi.stubEnv("CI", "true");
		expect(() => validateOptions("full", true)).toThrow("private_diagnostics_in_ci");
	});
	test("a module deadline cancels the module", async () => {
		const api = apiMock();
		vi.mocked(api.wait).mockImplementation(
			async (_id, _states, signal) =>
				new Promise((_, reject) =>
					signal.addEventListener("abort", () => reject(new HarnessError("module_timeout")), {
						once: true,
					}),
				),
		);
		await expect(execute(api, "abc", "op", vi.fn(), undefined, 10)).rejects.toThrow(
			"module_timeout",
		);
		expect(api.cancel).toHaveBeenCalledOnce();
	});
	test("a trigger failure cancels the module", async () => {
		const api = apiMock();
		await expect(
			execute(api, "abc", "rp", async () => {
				throw new HarnessError("browser_failed");
			}),
		).rejects.toThrow("browser_failed");
		expect(api.cancel).toHaveBeenCalledOnce();
	});
	test("external cancellation cancels the module", async () => {
		const api = apiMock(),
			controller = new AbortController();
		vi.mocked(api.wait).mockImplementation(
			async (_id, _states, signal) =>
				new Promise((_, reject) =>
					signal.addEventListener("abort", () => reject(new HarnessError("cancelled")), {
						once: true,
					}),
				),
		);
		const running = execute(api, "abc", "op", vi.fn(), controller.signal);
		controller.abort();
		await expect(running).rejects.toThrow("cancelled");
		expect(api.cancel).toHaveBeenCalledOnce();
	});
	test("a finished failed module is graded without retriggering", async () => {
		const api = apiMock(),
			trigger = vi.fn();
		vi.mocked(api.info).mockResolvedValue({ status: "FINISHED", result: "FAILED" });
		vi.mocked(api.logs).mockResolvedValue([{ result: "FAILURE" }]);
		const { info, logs } = await execute(api, "abc", "rp", trigger);
		expect(grade("ordinary", "rp", info, logs)).toBe(false);
		expect(trigger).not.toHaveBeenCalled();
		expect(api.cancel).not.toHaveBeenCalled();
		expect(api.start).not.toHaveBeenCalled();
	});
	test("an auto-started RP module in WAITING still triggers the application", async () => {
		const api = apiMock(),
			trigger = vi.fn().mockResolvedValue(undefined);
		vi.mocked(api.info)
			.mockResolvedValueOnce({ status: "WAITING" })
			.mockResolvedValue({ status: "FINISHED", result: "PASSED" });
		await execute(api, "abc", "rp", trigger);
		expect(api.wait).toHaveBeenNthCalledWith(
			1,
			"abc",
			["CONFIGURED", "WAITING", "FINISHED"],
			expect.any(AbortSignal),
		);
		expect(trigger).toHaveBeenCalledOnce();
		expect(api.cancel).not.toHaveBeenCalled();
	});
	test.each([ApplicationOutcomeError, ModuleFailure])(
		"preserves %s when suite module logs also fail",
		async (ErrorType) => {
			const state = await temp(),
				output = await temp();
			await writeFile(join(state, "settings.json"), JSON.stringify({ runId: "disposable" }));
			await writeFile(join(state, "ca.pem"), "test CA");
			await writeFile(join(state, "suite-keys.json"), "{}");
			vi.spyOn(ConformanceApi.prototype, "ready").mockResolvedValue(undefined);
			vi.spyOn(ConformanceApi.prototype, "fixturesReady").mockResolvedValue(undefined);
			vi.spyOn(ConformanceApi.prototype, "createModule").mockResolvedValue("instance");
			vi.spyOn(ConformanceApi.prototype, "wait").mockResolvedValue(undefined);
			vi.spyOn(ConformanceApi.prototype, "start").mockResolvedValue(undefined);
			vi.spyOn(ConformanceApi.prototype, "cancel").mockResolvedValue(undefined);
			vi.spyOn(ConformanceApi.prototype, "info")
				.mockResolvedValueOnce({ status: "CONFIGURED" })
				.mockResolvedValue({ status: "FINISHED", result: "FAILED" });
			vi.spyOn(ConformanceApi.prototype, "logs").mockResolvedValue([
				{ src: "ValidateToken", result: "FAILURE" },
			]);
			const login = vi.spyOn(ConformanceApi.prototype, "rpLogin");
			if (ErrorType === ApplicationOutcomeError)
				login.mockResolvedValue({
					status: 400,
					url: "https://rp.ofed.test:8443/callback",
					body: '{"accepted":false,"stage":"protocol"}',
				});
			else login.mockRejectedValue(new Error("private assertion"));
			const session = new Session("rp", state, output);
			await session.start();
			await expect(
				session.module("rp", "rp", plan(), "openid-federation-client-test", new Map(), new Map()),
			).rejects.toThrow(ErrorType);
			await session.finish();
			const report = JSON.parse(await readFile(join(output, "summary.json"), "utf8"));
			expect(report.passed).toBe(false);
			expect(report.failureKind).toBe(
				ErrorType === ApplicationOutcomeError ? "application" : "module",
			);
			expect(JSON.stringify(report)).not.toContain("private assertion");
			expect(session.halted).toBe(true);
		},
	);
});

describe("API client", () => {
	test("wait-state continues timed-out reads and accepts an observed lifecycle transition", async () => {
		const transport = vi
				.fn<typeof fetch>()
				.mockResolvedValueOnce(Response.json({ timeout: true }))
				.mockResolvedValueOnce(Response.json({ state: "WAITING" })),
			api = new ConformanceApi("test", transport);
		try {
			await api.wait("abc", ["CONFIGURED", "WAITING", "FINISHED"], AbortSignal.timeout(1000));
			expect(transport).toHaveBeenCalledTimes(2);
			for (const [url, options] of transport.mock.calls) {
				expect(new URL(String(url)).pathname).toBe("/api/runner/abc/wait-state");
				expect(new URL(String(url)).searchParams.get("states")).toBe(
					"CONFIGURED,WAITING,FINISHED,INTERRUPTED",
				);
				expect(options?.method).toBe("GET");
			}
		} finally {
			await api.close();
		}
	});
	test("wait-state rejects interrupted, malformed, and unexpected states", async () => {
		for (const body of [
			null,
			{},
			{ state: "private" },
			{ state: "RUNNING" },
			{ state: "INTERRUPTED" },
		]) {
			const transport = vi.fn<typeof fetch>().mockResolvedValue(Response.json(body)),
				api = new ConformanceApi("test", transport);
			try {
				await expect(api.wait("abc", ["FINISHED"], AbortSignal.timeout(1000))).rejects.toThrow(
					body?.state === "INTERRUPTED" ? "module_interrupted" : "api_invalid_state",
				);
				expect(transport).toHaveBeenCalledOnce();
			} finally {
				await api.close();
			}
		}
	});
	test("normalizes created and persisted plan IDs and rejects conflicting identities", async () => {
		const transport = vi.fn<typeof fetch>(),
			api = new ConformanceApi("test", transport);
		try {
			transport.mockResolvedValueOnce(Response.json(plan(), { status: 201 }));
			expect((await api.createPlan("test", {}, {})).id).toBe("plan");
			transport.mockResolvedValueOnce(Response.json({ _id: "plan", modules: plan().modules }));
			expect((await api.plan("plan")).id).toBe("plan");
			for (const identity of [
				{ _id: "other" },
				{ _id: "plan", id: "other" },
				{ _id: null },
				{ id: "../plan" },
				{},
			]) {
				transport.mockResolvedValueOnce(Response.json({ ...identity, modules: plan().modules }));
				await expect(api.plan("plan")).rejects.toThrow("api_invalid_plan");
			}
			transport.mockResolvedValueOnce(
				Response.json({ _id: "plan", modules: plan().modules }, { status: 201 }),
			);
			await expect(api.createPlan("test", {}, {})).rejects.toThrow("api_invalid_plan");
		} finally {
			await api.close();
		}
	});
	test("unexpected HTTP status cancels the body without exposing it or retrying", async () => {
		const response = new Response("private assertion", { status: 500 });
		if (!response.body) throw new Error("Expected a response body");
		const cancel = vi.spyOn(response.body, "cancel");
		const transport = vi.fn<typeof fetch>().mockResolvedValue(response),
			api = new ConformanceApi("test", transport);
		try {
			await expect(api.info("abc")).rejects.toThrow("api_http_status");
			expect(transport).toHaveBeenCalledOnce();
			expect(cancel).toHaveBeenCalledOnce();
		} finally {
			await api.close();
		}
	});
	test("malformed JSON and invalid API shapes fail", async () => {
		for (const body of [
			"{private",
			"null",
			'"payload"',
			"{}",
			'{"status":"private assertion"}',
			'{"status":"FINISHED","result":{"private_key":"secret"}}',
		]) {
			const api = new ConformanceApi(
				"test",
				vi.fn<typeof fetch>().mockResolvedValue(new Response(body)),
			);
			try {
				await expect(api.info("abc")).rejects.toThrow(HarnessError);
			} finally {
				await api.close();
			}
		}
	});
	test("module IDs are encoded and state-changing calls are not retried", async () => {
		const transport = vi
				.fn<typeof fetch>()
				.mockResolvedValue(Response.json({ id: "module" }, { status: 201 })),
			api = new ConformanceApi("test", transport);
		try {
			await api.createModule("plan", "module", BASELINE.variants);
			expect(transport).toHaveBeenCalledOnce();
			expect(transport.mock.calls[0]?.[1]?.method).toBe("POST");
			expect(transport.mock.calls[0]?.[1]?.redirect).toBe("error");
			transport.mockResolvedValueOnce(Response.json({ status: "FINISHED" }));
			await api.info("a/b?x=1");
			expect(String(transport.mock.calls[1]?.[0])).toContain("a%2Fb%3Fx%3D1");
		} finally {
			await api.close();
		}
	});
	test("body limits reject and cancel an oversized stream", async () => {
		const response = new Response("12345");
		if (!response.body) throw new Error("Expected a response body");
		const cancel = vi.spyOn(response.body, "getReader");
		await expect(readBody(response, 4)).rejects.toThrow("oversized_response");
		expect(cancel).toHaveBeenCalledOnce();
		expect(response.body?.locked).toBe(false);
	});
});

describe("HTTPS transport", () => {
	let directory: string, ca: string, base: string;
	const server = createServer();
	const received = new Set<string>();
	beforeAll(async () => {
		directory = await mkdtemp(join(tmpdir(), "oidfed-harness-tls-"));
		await promisify(execFile)("openssl", [
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-nodes",
			"-days",
			"1",
			"-subj",
			"/CN=localhost",
			"-addext",
			"subjectAltName=IP:127.0.0.1",
			"-keyout",
			join(directory, "key.pem"),
			"-out",
			join(directory, "ca.pem"),
		]);
		ca = await readFile(join(directory, "ca.pem"), "utf8");
		server.setSecureContext({ key: await readFile(join(directory, "key.pem")), cert: ca });
		server.on("request", (req, res) => {
			received.add(req.url ?? "");
			if (req.url?.includes("stall")) return;
			if (req.url?.includes("redirect")) {
				res.writeHead(302, { Location: "/api/info/abc" }).end();
				return;
			}
			if (req.url?.includes("slow-body")) {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.flushHeaders();
				return;
			}
			res.setHeader("Content-Type", "application/json");
			res.end('{"status":"FINISHED","result":"PASSED"}');
		});
		await new Promise<void>((done, reject) => {
			server.once("error", reject);
			server.listen(0, "127.0.0.1", done);
		});
		const address = server.address();
		if (!address || typeof address === "string") throw new Error("Missing test listener");
		base = `https://127.0.0.1:${address.port}`;
	});
	afterAll(async () => {
		server.closeAllConnections();
		await new Promise<void>((done) => server.close(() => done()));
		await rm(directory, { recursive: true, force: true });
	});
	test("accepts its pinned CA and rejects an untrusted certificate", async () => {
		const trusted = new ConformanceApi(ca, fetch, base),
			untrusted = new ConformanceApi("", fetch, base);
		try {
			expect((await trusted.info("abc")).result).toBe("PASSED");
			await expect(untrusted.info("abc")).rejects.toThrow("api_request_failed");
		} finally {
			await trusted.close();
			await untrusted.close();
		}
	});
	test("rejects redirects on suite API calls", async () => {
		const api = new ConformanceApi(ca, fetch, base);
		try {
			await expect(api.info("redirect")).rejects.toThrow("api_request_failed");
		} finally {
			await api.close();
		}
	});
	test.each(["stall", "slow-body"])("bounds %s responses through body completion", async (name) => {
		const api = new ConformanceApi(ca, fetch, base, 200);
		try {
			await expect(api.info(name)).rejects.toThrow(HarnessError);
			expect(received.has(`/api/info/${name}`)).toBe(true);
		} finally {
			await api.close();
		}
	});
});
