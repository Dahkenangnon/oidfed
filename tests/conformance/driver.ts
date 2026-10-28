/** Run the pinned modules and retain the existing report and acceptance contracts. */
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { isDeepStrictEqual } from "node:util";
import { ConformanceApi, SUITE, type SuiteApi } from "./api.js";
import { checkExport } from "./exports.js";
import {
	ApplicationOutcomeError,
	BASELINE,
	diagnostics,
	grade,
	HarnessError,
	instances,
	inventory,
	type LogEntry,
	ModuleFailure,
	type ModuleInfo,
	type ModuleRecord,
	moduleVariant,
	type PlanInfo,
	type Profile,
	type Report,
	type Role,
	recordError,
	rpOutcome,
} from "./policy.js";

export async function execute(
	api: SuiteApi,
	id: string,
	role: Role,
	trigger: (signal: AbortSignal) => Promise<void>,
	external?: AbortSignal,
	timeout = 180_000,
): Promise<{ info: ModuleInfo; logs: LogEntry[] }> {
	let completed = false;
	const deadline = AbortSignal.timeout(timeout);
	const signal = AbortSignal.any([deadline, ...(external ? [external] : [])]);
	try {
		// These modules auto-start. RP modules may already be waiting for the application.
		await api.wait(id, ["CONFIGURED", "WAITING", "FINISHED"], signal);
		const initial = await api.info(id, signal);
		if (initial.status !== "FINISHED") {
			await api.start(id, signal);
			if (role === "rp") await trigger(signal);
			await api.wait(id, ["FINISHED"], signal);
		}
		const info = await api.info(id, signal);
		const logs = await api.logs(id, signal);
		completed = info.status === "FINISHED";
		return { info, logs };
	} catch (error) {
		if (!(error instanceof ApplicationOutcomeError) && deadline.aborted && !external?.aborted)
			throw new HarnessError("module_timeout");
		throw error;
	} finally {
		// Cleanup gets its own deadline, independent of the aborted test signal.
		if (!completed) await api.cancel(id).catch(() => {});
	}
}

export function configuration(
	role: Role,
	target: string,
	runId: string,
	keys: Record<string, unknown>,
): Record<string, unknown> {
	const alias = role === "deployed" ? `${runId}-${role}-${target}` : `${runId}-${role}`;
	const federation: Record<string, unknown> = {
		entity_identifier: `https://${target}.ofed.test:8443`,
	};
	const config: Record<string, unknown> = {
		alias,
		description: "Disposable oidfed conformance fixture",
		publish: "no",
		federation,
	};
	if (role === "deployed")
		Object.assign(federation, {
			de_trust_anchor: "https://ta.ofed.test:8443",
			de_trust_anchor_jwks: { keys: [keys.anchorPublic] },
		});
	else {
		config.federation_trust_anchor = { trust_anchor_jwks: { keys: [keys.authority] } };
		if (role === "op") {
			Object.assign(federation, {
				rp_ec_jwks: { keys: [keys.entity] },
				rp_client_jwks: { keys: [keys.protocol] },
			});
			config.client = { scope: "openid" };
			config.browser = [
				{
					match: "https://op.ofed.test:8443/auth*",
					tasks: [
						{
							task: "Verify Complete",
							match: `${SUITE}/test/a/${alias}/callback*`,
							commands: [["wait", "id", "submission_complete", 15]],
						},
					],
				},
			];
		} else
			Object.assign(federation, {
				op_ec_jwks: { keys: [keys.entity] },
				op_server_jwks: { keys: [keys.protocol, keys.encryption] },
			});
	}
	return config;
}

export class Session {
	readonly report: Report;
	private api?: ConformanceApi;
	private keys: Record<string, unknown> = {};
	private runId = "";
	halted = false;
	constructor(
		readonly profile: Profile,
		readonly state = "/run/oidfed",
		readonly output = "/results",
	) {
		this.report = { revision: BASELINE.revision, profile, modules: [], passed: false };
	}
	private client(): ConformanceApi {
		if (!this.api) throw new HarnessError("session_not_ready");
		return this.api;
	}
	async privateLog(name: string, value: unknown): Promise<void> {
		await writeFile(join(this.state, name), JSON.stringify(value), { mode: 0o600 });
	}
	async fail(error: unknown): Promise<void> {
		this.halted = true;
		recordError(this.report, error);
		await this.privateLog(
			"driver-private.log",
			error instanceof Error
				? { name: error.name, message: error.message, stack: error.stack }
				: { name: "UnknownError" },
		);
		await this.save();
	}
	async save(): Promise<void> {
		await mkdir(this.output, { recursive: true });
		await writeFile(join(this.output, "summary.json"), `${JSON.stringify(this.report, null, 2)}\n`);
	}
	async start(): Promise<void> {
		this.report.phase = "startup";
		try {
			this.runId = (
				JSON.parse(await readFile(join(this.state, "settings.json"), "utf8")) as { runId: string }
			).runId;
			this.api = new ConformanceApi(await readFile(join(this.state, "ca.pem"), "utf8"));
			const signal = AbortSignal.timeout(360_000);
			await this.api.ready(signal);
			while (!signal.aborted) {
				try {
					await this.api.fixturesReady(signal);
					this.keys = JSON.parse(
						await readFile(join(this.state, "suite-keys.json"), "utf8"),
					) as Record<string, unknown>;
					return;
				} catch {
					await delay(1000, undefined, { signal }).catch(() => {});
				}
			}
			throw new HarnessError("startup_timeout");
		} catch (error) {
			await this.fail(error);
			throw this.publicError(error);
		}
	}
	publicError(error: unknown): HarnessError {
		return error instanceof HarnessError ? error : new HarnessError("orchestration_failed");
	}
	async createPlan(role: Role, target: string): Promise<PlanInfo> {
		this.report.phase = `${role}-${target}:create-plan`;
		const plan = await this.client().createPlan(
			BASELINE.plans[role].name,
			configuration(role, target, this.runId, this.keys),
			BASELINE.variants,
		);
		inventory(plan, role);
		return plan;
	}
	async module(
		role: Role,
		target: string,
		plan: PlanInfo,
		name: string,
		executed: Map<string, string>,
		expected: Map<string, [string | undefined, string | undefined]>,
		signal?: AbortSignal,
	): Promise<ModuleRecord> {
		const record: ModuleRecord = {
			name,
			target,
			status: "INCOMPLETE",
			result: "UNKNOWN",
			accepted: false,
			diagnostics: [],
		};
		this.report.modules.push(record);
		this.report.phase = "create-module";
		const api = this.client();
		try {
			const id = await api.createModule(plan.id, name, BASELINE.variants, signal);
			executed.set(name, id);
			this.report.phase = "execute-module";
			let outcome: Awaited<ReturnType<typeof execute>>;
			try {
				outcome = await execute(
					api,
					id,
					role,
					async (abort) => {
						const response = await api.rpLogin(abort);
						await this.privateLog(`rp-${name}-response.json`, response);
						rpOutcome(name, response.status, JSON.parse(response.body));
					},
					signal,
				);
			} catch (error) {
				let logs: LogEntry[] = [];
				try {
					const cleanup = AbortSignal.timeout(5000);
					logs = await api.logs(id, cleanup);
					await this.privateLog(`${target}-${name}.json`, logs);
					record.diagnostics = diagnostics(logs);
					const info = await api.info(id, cleanup);
					record.status = info.status ?? "INCOMPLETE";
					record.result = info.result ?? "UNKNOWN";
				} catch {
					/* Keep the primary failure when diagnostics are unavailable. */
				}
				if (!(error instanceof ApplicationOutcomeError) && logs.some((x) => x.result === "FAILURE"))
					throw new ModuleFailure("foundation_module_failed");
				throw error;
			}
			moduleVariant(outcome.info);
			await this.privateLog(`${target}-${name}.json`, outcome.logs);
			expected.set(id, [outcome.info.status, outcome.info.result]);
			Object.assign(record, {
				status: outcome.info.status,
				result: outcome.info.result,
				accepted: grade(name, target, outcome.info, outcome.logs),
				diagnostics: diagnostics(outcome.logs),
			});
			return record;
		} catch (error) {
			await this.fail(error);
			throw this.publicError(error);
		} finally {
			await this.save();
		}
	}
	async verifyPlan(
		role: Role,
		plan: PlanInfo,
		executed: Map<string, string>,
		expected: Map<string, [string | undefined, string | undefined]>,
	): Promise<void> {
		try {
			this.report.phase = "verify-plan";
			const finalPlan = await this.client().plan(plan.id);
			if (!isDeepStrictEqual(finalPlan.variant, BASELINE.variants))
				throw new HarnessError("plan_variant_mismatch");
			inventory(finalPlan, role);
			instances(finalPlan, executed);
			this.report.phase = "verify-export";
			const temp = await mkdtemp(join(this.state, "export-"));
			try {
				const path = join(temp, "export.zip");
				const response = await this.client().export(plan.id);
				if (!response.body) throw new HarnessError("invalid_export");
				const file = await open(path, "wx", 0o600);
				const reader = response.body.getReader();
				try {
					while (true) {
						const part = await reader.read();
						if (part.done) break;
						await file.writeFile(part.value);
					}
				} finally {
					await reader.cancel().catch(() => {});
					reader.releaseLock();
					await file.close();
				}
				await checkExport(path, expected);
			} finally {
				await rm(temp, { recursive: true, force: true });
			}
		} catch (error) {
			await this.fail(error);
			throw this.publicError(error);
		}
	}
	async finish(): Promise<void> {
		if (!this.halted) {
			this.report.passed =
				this.report.modules.length > 0 && this.report.modules.every((x) => x.accepted);
			this.report.phase = "complete";
		}
		try {
			await this.save();
		} finally {
			await this.api?.close();
		}
	}
}
