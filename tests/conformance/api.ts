/** Small client for the pinned OpenID Foundation conformance suite API; it contains no protocol assertions. */
import { setTimeout as delay } from "node:timers/promises";
import { Agent, fetch, type Response } from "undici";
import { HarnessError, type LogEntry, type ModuleInfo, type PlanInfo } from "./policy.js";

export const SUITE = "https://suite.ofed.test:8443";
export const MAX_ENTRY_BYTES = 50_000_000;
type Fetch = typeof fetch;
// Lifecycle values defined by TestModule.java in the pinned OpenID Foundation conformance suite.
const STATUSES = new Set([
	"NOT_YET_CREATED",
	"CREATED",
	"CONFIGURED",
	"RUNNING",
	"WAITING",
	"INTERRUPTED",
	"FINISHED",
]);
const RESULTS = new Set(["PASSED", "FAILED", "WARNING", "REVIEW", "SKIPPED", "UNKNOWN"]);
const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/;

export async function readBody(response: Response, limit = MAX_ENTRY_BYTES): Promise<Buffer> {
	const chunks: Uint8Array[] = [];
	let size = 0;
	if (!response.body) return Buffer.alloc(0);
	const reader = response.body.getReader();
	try {
		while (true) {
			const part = await reader.read();
			if (part.done) break;
			size += part.value.byteLength;
			if (size > limit) throw new HarnessError("oversized_response");
			chunks.push(part.value);
		}
		return Buffer.concat(chunks);
	} finally {
		await reader.cancel().catch(() => {});
		reader.releaseLock();
	}
}

export interface SuiteApi {
	info(id: string, signal?: AbortSignal): Promise<ModuleInfo>;
	logs(id: string, signal?: AbortSignal): Promise<LogEntry[]>;
	start(id: string, signal?: AbortSignal): Promise<void>;
	wait(id: string, states: string[], signal: AbortSignal): Promise<void>;
	cancel(id: string): Promise<void>;
}

export class ConformanceApi implements SuiteApi {
	private readonly agent: Agent;
	constructor(
		ca: string,
		private readonly transport: Fetch = fetch,
		private readonly base = SUITE,
		private readonly requestTimeout = 20_000,
	) {
		this.agent = new Agent({ connect: { ca } });
	}

	private async response(
		path: string,
		method: string,
		expected: number,
		signal?: AbortSignal,
		body?: string,
	): Promise<Response> {
		try {
			const response = await this.transport(new URL(path, `${this.base}/`), {
				method,
				redirect: "error",
				dispatcher: this.agent,
				signal: AbortSignal.any([
					AbortSignal.timeout(this.requestTimeout),
					...(signal ? [signal] : []),
				]),
				headers: { "Content-Type": "application/json" },
				...(body !== undefined ? { body } : {}),
			});
			if (response.status !== expected) {
				await response.body?.cancel().catch(() => {});
				throw new HarnessError("api_http_status");
			}
			return response;
		} catch (error) {
			if (error instanceof HarnessError) throw error;
			throw new HarnessError(signal?.aborted ? "cancelled" : "api_request_failed");
		}
	}

	private async json(
		path: string,
		method = "GET",
		expected = 200,
		signal?: AbortSignal,
		body?: string,
	): Promise<unknown> {
		try {
			return JSON.parse(
				(await readBody(await this.response(path, method, expected, signal, body))).toString(),
			);
		} catch (error) {
			if (error instanceof HarnessError) throw error;
			throw new HarnessError(
				error instanceof SyntaxError ? "api_invalid_json" : "api_response_failed",
			);
		}
	}

	async ready(signal: AbortSignal): Promise<void> {
		while (!signal.aborted) {
			try {
				await this.json("api/plan?length=1", "GET", 200, signal);
				return;
			} catch {
				await delay(1000, undefined, { signal }).catch(() => {});
			}
		}
		throw new HarnessError("startup_timeout");
	}
	async fixturesReady(signal: AbortSignal): Promise<void> {
		const response = await this.response("https://rp.ofed.test:8443/health", "GET", 200, signal);
		await response.body?.cancel();
	}

	async createPlan(
		name: string,
		configuration: unknown,
		variant: unknown,
		signal?: AbortSignal,
	): Promise<PlanInfo> {
		const query = new URLSearchParams({ planName: name, variant: JSON.stringify(variant) });
		return this.parsePlan(
			await this.json(`api/plan?${query}`, "POST", 201, signal, JSON.stringify(configuration)),
		);
	}
	async plan(id: string, signal?: AbortSignal): Promise<PlanInfo> {
		return this.parsePlan(
			await this.json(`api/plan/${encodeURIComponent(id)}`, "GET", 200, signal),
			id,
		);
	}
	private parsePlan(value: unknown, expectedId?: string): PlanInfo {
		// Creation returns `id`; the persisted Plan returned by GET uses MongoDB's `_id`.
		const id =
			value && typeof value === "object"
				? expectedId !== undefined && "_id" in value
					? value._id
					: "id" in value
						? value.id
						: undefined
				: undefined;
		if (
			!value ||
			typeof value !== "object" ||
			typeof id !== "string" ||
			!IDENTIFIER.test(id) ||
			(expectedId !== undefined && (id !== expectedId || ("id" in value && value.id !== id))) ||
			!("modules" in value) ||
			!Array.isArray(value.modules) ||
			value.modules.some((x) => !x || typeof x.testModule !== "string")
		)
			throw new HarnessError("api_invalid_plan");
		return { ...value, id } as PlanInfo;
	}
	async createModule(
		plan: string,
		test: string,
		variant: unknown,
		signal?: AbortSignal,
	): Promise<string> {
		const query = new URLSearchParams({ plan, test, variant: JSON.stringify(variant) });
		const value = await this.json(`api/runner?${query}`, "POST", 201, signal);
		if (
			!value ||
			typeof value !== "object" ||
			!("id" in value) ||
			typeof value.id !== "string" ||
			!IDENTIFIER.test(value.id)
		)
			throw new HarnessError("api_invalid_module");
		return value.id;
	}
	async info(id: string, signal?: AbortSignal): Promise<ModuleInfo> {
		const value = await this.json(`api/info/${encodeURIComponent(id)}`, "GET", 200, signal);
		if (
			!value ||
			typeof value !== "object" ||
			!("status" in value) ||
			typeof value.status !== "string" ||
			!STATUSES.has(value.status)
		)
			throw new HarnessError("api_invalid_module");
		const result = "result" in value ? value.result : undefined;
		if (result != null && (typeof result !== "string" || !RESULTS.has(result)))
			throw new HarnessError("api_invalid_module");
		return {
			status: value.status,
			...(typeof result === "string" ? { result } : {}),
			...("variant" in value ? { variant: value.variant } : {}),
		};
	}
	async logs(id: string, signal?: AbortSignal): Promise<LogEntry[]> {
		const value = await this.json(`api/log/${encodeURIComponent(id)}`, "GET", 200, signal);
		if (!Array.isArray(value) || value.some((x) => !x || typeof x !== "object"))
			throw new HarnessError("api_invalid_logs");
		return value as LogEntry[];
	}
	async start(id: string, signal?: AbortSignal): Promise<void> {
		const response = await this.response(
			`api/runner/${encodeURIComponent(id)}`,
			"POST",
			200,
			signal,
		);
		await response.body?.cancel();
	}
	async wait(id: string, states: string[], signal: AbortSignal): Promise<void> {
		const query = new URLSearchParams({
			states: [...new Set([...states, "INTERRUPTED"])].join(","),
			timeoutMs: "10000",
		});
		while (!signal.aborted) {
			// The runner observes transitions directly; polling persisted info can miss CONFIGURED.
			const value = await this.json(
				`api/runner/${encodeURIComponent(id)}/wait-state?${query}`,
				"GET",
				200,
				signal,
			);
			if (!value || typeof value !== "object") throw new HarnessError("api_invalid_state");
			if ("timeout" in value && value.timeout === true && !("state" in value)) continue;
			if (!("state" in value) || typeof value.state !== "string")
				throw new HarnessError("api_invalid_state");
			if (value.state === "INTERRUPTED") throw new HarnessError("module_interrupted");
			if (states.includes(value.state)) return;
			throw new HarnessError("api_invalid_state");
		}
		throw new HarnessError("module_timeout");
	}
	async cancel(id: string): Promise<void> {
		const response = await this.response(
			`api/runner/${encodeURIComponent(id)}`,
			"DELETE",
			200,
			AbortSignal.timeout(5000),
		);
		await response.body?.cancel();
	}
	async export(id: string, signal?: AbortSignal): Promise<Response> {
		return this.response(`api/plan/export/${encodeURIComponent(id)}`, "GET", 200, signal);
	}
	async rpLogin(signal: AbortSignal): Promise<{ status: number; url: string; body: string }> {
		try {
			const response = await this.transport("https://rp.ofed.test:8443/login", {
				dispatcher: this.agent,
				redirect: "follow",
				signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
			});
			return {
				status: response.status,
				url: response.url,
				body: (await readBody(response)).toString(),
			};
		} catch {
			throw new HarnessError("rp_request_failed");
		}
	}
	async close(): Promise<void> {
		await this.agent.close();
	}
}
