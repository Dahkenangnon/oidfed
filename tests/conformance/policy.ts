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
	suspension?: { revision: string; reason: string };
}
export interface Report {
	revision: string;
	profile: Profile;
	modules: ModuleRecord[];
	passed: boolean;
	coverage: "complete" | "partial";
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

const SUSPENSION_REVISION = "23353b36957d6466010de767c812d2c91ed37638";

// These pinned OP cases create conditional manual-review prompts. Keep them out
// of unattended execution until those reviews can be resolved from evidence.
const OP_MANUAL_REVIEW = new Set([
	"openid-federation-automatic-client-registration-invalid-client-id-in-request-object",
	"openid-federation-automatic-client-registration-invalid-client-id-in-query-parameters",
	"openid-federation-automatic-client-registration-invalid-signature-on-request-object",
	"openid-federation-automatic-client-registration-invalid-signature-with-other-keys-on-request-object",
	"openid-federation-automatic-client-registration-invalid-request-object-exp",
	"openid-federation-automatic-client-registration-invalid-request-object-iss",
	"openid-federation-automatic-client-registration-invalid-request-object-aud",
	"openid-federation-automatic-client-registration-invalid-request-object-sub",
	"openid-federation-automatic-client-registration-invalid-missing-request-object-jti",
	"openid-federation-automatic-client-registration-invalid-missing-request-object-exp",
	"openid-federation-automatic-client-registration-invalid-missing-request-object-iss",
	"openid-federation-automatic-client-registration-invalid-missing-request-object-aud",
	"openid-federation-automatic-client-registration-invalid-duplicate-request-object-jti",
]);

// The shared upstream tokenResponse() omits access_token and token_type. These
// four flows cannot exercise their intended assertions until that response is fixed.
const RP_TOKEN_RESPONSE = new Set([
	"openid-federation-client-test",
	"openid-federation-client-valid-unknown-client-registration-types-supported",
	"openid-federation-client-invalid-aud-in-id-token",
	"openid-federation-client-invalid-iss-in-id-token",
]);

/** Temporary exclusions apply only to these exact modules and this reviewed suite revision. */
export function suspensionReason(
	role: Role,
	name: string,
	revision = BASELINE.revision,
): string | undefined {
	if (revision !== SUSPENSION_REVISION) throw new HarnessError("suspensions_require_review");
	if (role === "op" && OP_MANUAL_REVIEW.has(name))
		return "Pinned OP case requires manual error-page review; automated review is not implemented";
	if (role === "rp" && RP_TOKEN_RESPONSE.has(name))
		return "Pinned RP token response omits required access_token and token_type";
	return undefined;
}

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

export function instances(
	plan: PlanInfo,
	executed: Map<string, string>,
	role: Role = "deployed",
): void {
	if (
		plan.modules.filter((x) => !suspensionReason(role, x.testModule)).length !== executed.size ||
		plan.modules.some((x) =>
			suspensionReason(role, x.testModule)
				? executed.has(x.testModule) ||
					(x.instances !== undefined && !isDeepStrictEqual(x.instances, []))
				: !executed.has(x.testModule) ||
					!isDeepStrictEqual(x.instances, [executed.get(x.testModule)]),
		)
	)
		throw new HarnessError("module_execution_mismatch");
}

/** A recorded suspension is unexecuted, revision-bound, and never an accepted protocol result. */
export function completedRecord(record: ModuleRecord): boolean {
	if (!record || typeof record !== "object") return false;
	if (record.suspension !== undefined) {
		const role = record.target === "op" ? "op" : record.target === "rp" ? "rp" : undefined;
		const reason = role ? suspensionReason(role, record.name) : undefined;
		return (
			reason !== undefined &&
			record.status === "NOT_RUN" &&
			record.result === "SKIPPED" &&
			record.accepted === false &&
			record.suspension?.revision === BASELINE.revision &&
			record.suspension?.reason === reason &&
			Array.isArray(record.diagnostics) &&
			record.diagnostics.length === 0
		);
	}
	if (record.accepted !== true || record.status !== "FINISHED") return false;
	if (record.result === "PASSED") return true;
	return (
		record.result === "SKIPPED" &&
		((record.target === "op" && record.name === ENCRYPTED) ||
			(record.target === "leaf" && FETCH_MODULES.has(record.name)))
	);
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
	if (report.modules.some((record) => !completedRecord(record)))
		throw new HarnessError("incomplete_report");
	const coverage = report.modules.some((record) => record.suspension !== undefined)
		? "partial"
		: "complete";
	if (report.coverage !== coverage) throw new HarnessError("incomplete_report");
	const found = report.modules.map((record) => `${record.target}:${record.name}`).sort();
	if (!isDeepStrictEqual(wanted, found)) throw new HarnessError("incomplete_report");
}
