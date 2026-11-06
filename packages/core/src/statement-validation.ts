import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	InternalErrorCode,
	STANDARD_ENTITY_STATEMENT_CLAIMS,
} from "./constants.js";
import { err, type FederationError, ok, type Result } from "./errors.js";
import { type FederationOptions, nowSeconds } from "./types.js";

/** Enforce payload critical claims under Federation §3.1.1. Callers process the extensions they declare understood. */
export function validateCriticalClaims(
	payload: Readonly<Record<string, unknown>>,
	understood: ReadonlySet<string> = new Set(),
): Result<void, FederationError> {
	const crit = payload.crit;
	if (crit === undefined) return ok(undefined);
	const fail = (description: string): Result<void, FederationError> =>
		err({ code: InternalErrorCode.TrustChainInvalid, description });
	if (
		!Array.isArray(crit) ||
		crit.length === 0 ||
		!crit.every((claim) => typeof claim === "string")
	) {
		return fail("crit must be an array of claim names");
	}
	const seen = new Set<string>();
	for (const claim of crit) {
		if (seen.has(claim)) return fail(`Duplicate claim '${claim}' in crit`);
		seen.add(claim);
		if (STANDARD_ENTITY_STATEMENT_CLAIMS.has(claim)) {
			return fail(`Standard claim '${claim}' MUST NOT appear in crit`);
		}
		if (!understood.has(claim)) return fail(`Unknown critical claim '${claim}'`);
		if (!Object.hasOwn(payload, claim)) {
			return fail(`Claim '${claim}' listed in crit does not exist in JWT payload`);
		}
	}
	return ok(undefined);
}

/** Check required Entity Statement times using the verifier's clock and allowed skew (§3.2). */
export function validateEntityStatementTimeClaims(
	payload: Readonly<Record<string, unknown>>,
	options?: Pick<FederationOptions, "clock" | "clockSkewSeconds">,
): Result<void, FederationError & { readonly field: "iat" | "exp" }> {
	const now = nowSeconds(options?.clock);
	const skew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	for (const field of ["iat", "exp"] as const) {
		const value = payload[field];
		if (typeof value !== "number" || !Number.isFinite(value)) {
			return err({
				code: InternalErrorCode.TrustChainInvalid,
				field,
				description: `'${field}' is missing or is not a finite NumericDate`,
			});
		}
		if (field === "iat" && value > now + skew) {
			return err({
				code: InternalErrorCode.TrustChainInvalid,
				field,
				description: "'iat' is in the future",
			});
		}
		if (field === "exp" && value <= now - skew) {
			return err({
				code: InternalErrorCode.Expired,
				field,
				description: "Entity Statement has expired",
			});
		}
	}
	return ok(undefined);
}
