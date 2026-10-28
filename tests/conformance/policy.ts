/** Acceptance rules for the pinned OpenID Federation conformance test plans. */
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";

export const BASELINE = JSON.parse(
	readFileSync(new URL("./baseline.json", import.meta.url), "utf8"),
) as {
	revision: string;
	repository: string;
	variants: Record<string, string>;
	plans: Record<
		Role,
		{ name: string; source: string; modules: { name: string; source: string }[] }
	>;
	profiles: Record<Profile, Role[]>;
};
export type Role = "deployed" | "rp" | "op";
export type Profile = Role | "full";
export interface ModuleInfo {
	status?: string;
	result?: string;
	variant?: unknown;
}
export interface LogEntry {
	result?: string;
	msg?: string;
	src?: string;
}
export interface PlanInfo {
	id: string;
	variant?: unknown;
	modules: { testModule: string; variant?: unknown; instances?: string[] }[];
}
export interface ModuleRecord {
	name: string;
	target: string;
	status: string;
	result: string;
	accepted: boolean;
	diagnostics: { source: string; result: string }[];
}
export interface Report {
	revision: string;
	profile: Profile;
	modules: ModuleRecord[];
	passed: boolean;
	phase?: string;
	errorClass?: string;
	failureKind?: string;
	errorCode?: string;
}

/** Messages are fixed codes; never attach response bodies or raw error causes. */
export class HarnessError extends Error {
	constructor(code: string) {
		super(code);
		this.name = new.target.name;
	}
}
export class ApplicationOutcomeError extends HarnessError {}
export class ModuleFailure extends HarnessError {}

export const ENCRYPTED =
	"openid-federation-automatic-client-registration-with-jar-and-encrypted-request-object";
const FETCH_MODULES = new Set([
	"openid-federation-ensure-fetch-with-invalid-sub-fails",
	"openid-federation-ensure-fetch-with-iss-as-sub-fails",
]);

export function grade(name: string, target: string, info: ModuleInfo, logs: LogEntry[]): boolean {
	if (
		info.status !== "FINISHED" ||
		!logs.length ||
		logs.some((x) => ["FAILURE", "WARNING", "REVIEW"].includes(x.result ?? ""))
	)
		return false;
	if (info.result === "PASSED") return true;
	if (info.result !== "SKIPPED") return false;
	const reasons = logs.filter((x) => x.result === "SKIPPED").map((x) => x.msg);
	if (name === ENCRYPTED)
		return reasons.includes(
			"The test was skipped: The server does not support encrypted request objects",
		);
	return (
		FETCH_MODULES.has(name) &&
		target === "leaf" &&
		reasons.includes(
			"The test was skipped: Entity metadata does not contain a federation_fetch_endpoint.",
		)
	);
}

export function inventory(plan: PlanInfo, role: Role): void {
	const names = plan.modules.map((x) => x.testModule);
	const wanted = BASELINE.plans[role].modules.map((x) => x.name);
	if (
		new Set(names).size !== names.length ||
		!isDeepStrictEqual([...names].sort(), [...wanted].sort())
	)
		throw new HarnessError("plan_inventory_mismatch");
	// These plan definitions have no fixed module-variant overrides.
	if (plan.modules.some((x) => x.variant != null))
		throw new HarnessError("module_variant_mismatch");
}

export function moduleVariant(info: ModuleInfo): void {
	if (!isDeepStrictEqual(info.variant, BASELINE.variants))
		throw new HarnessError("module_variant_mismatch");
}

export function instances(plan: PlanInfo, executed: Map<string, string>): void {
	if (
		plan.modules.length !== executed.size ||
		plan.modules.some((x) => !isDeepStrictEqual(x.instances, [executed.get(x.testModule)]))
	)
		throw new HarnessError("module_execution_mismatch");
}

export function rpOutcome(name: string, status: number, body: unknown): void {
	const positive = [
		"openid-federation-client-test",
		"openid-federation-client-valid-unknown-client-registration-types-supported",
	].includes(name);
	const stages =
		positive || name.endsWith("-in-id-token") ? ["protocol"] : ["federation", "registration"];
	if (
		!body ||
		typeof body !== "object" ||
		!("accepted" in body) ||
		!("stage" in body) ||
		status !== (positive ? 200 : 400) ||
		body.accepted !== positive ||
		typeof body.stage !== "string" ||
		!stages.includes(body.stage)
	)
		throw new ApplicationOutcomeError("rp_outcome_mismatch");
}

export function diagnostics(logs: LogEntry[]): ModuleRecord["diagnostics"] {
	return logs
		.filter((x) => ["FAILURE", "WARNING", "REVIEW"].includes(x.result ?? ""))
		.map((x) => ({
			source: typeof x.src === "string" && /^[\w.$-]{1,180}$/.test(x.src) ? x.src : "unknown",
			result: x.result ?? "UNKNOWN",
		}));
}

export function recordError(report: Report, error: unknown): void {
	report.passed = false;
	report.errorClass = error instanceof HarnessError ? error.name : "Error";
	report.failureKind =
		error instanceof ApplicationOutcomeError
			? "application"
			: error instanceof ModuleFailure
				? "module"
				: "orchestration";
	if (error instanceof HarnessError) report.errorCode = error.message;
}

/** A successful test process must still have produced a complete profile report. */
export function ensureComplete(value: unknown, profile: Profile): void {
	if (!value || typeof value !== "object") throw new HarnessError("incomplete_report");
	const report = value as Report;
	if (
		report.passed !== true ||
		report.profile !== profile ||
		report.revision !== BASELINE.revision ||
		!Array.isArray(report.modules)
	)
		throw new HarnessError("incomplete_report");
	const wanted = BASELINE.profiles[profile]
		.flatMap((role) =>
			(role === "deployed" ? ["ta", "ia", "leaf"] : [role]).flatMap((target) =>
				BASELINE.plans[role].modules.map((module) => `${target}:${module.name}`),
			),
		)
		.sort();
	if (report.modules.some((record) => record?.accepted !== true || record.status !== "FINISHED"))
		throw new HarnessError("incomplete_report");
	const found = report.modules.map((record) => `${record.target}:${record.name}`).sort();
	if (!isDeepStrictEqual(wanted, found)) throw new HarnessError("incomplete_report");
}
