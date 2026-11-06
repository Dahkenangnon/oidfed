import { DEFAULT_CLOCK_SKEW_SECONDS, InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import {
	type FederationOptions,
	nowSeconds,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
} from "../types.js";

/** Application accreditation requirements, applied after Federation chain validation. */
export interface TrustMarkRequirements {
	readonly requiredTypes?: readonly string[];
	readonly requireAllPublished?: boolean;
}

/**
 * Check application requirements against freshly validated evidence.
 * Checks chain expiry and rechecks mark and delegation dates. Applications obtain fresh issuer
 * evidence and check active status separately when their policy requires it.
 */
export function checkTrustMarkRequirements(
	chain: ValidatedTrustChain,
	requirements: TrustMarkRequirements,
	options?: Pick<FederationOptions, "clock" | "clockSkewSeconds">,
): Result<void, FederationError> {
	const now = nowSeconds(options?.clock);
	const skew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	if (chain.expiresAt <= now) {
		return err({
			code: InternalErrorCode.TrustChainInvalid,
			description:
				"Chain evidence has expired; validate fresh evidence before checking accreditation",
		});
	}
	const current = (mark: ValidatedTrustMark) =>
		mark.issuedAt <= now + skew &&
		(mark.expiresAt === undefined || mark.expiresAt > now - skew) &&
		(!mark.delegation ||
			(mark.delegation.issuedAt <= now + skew &&
				(mark.delegation.expiresAt === undefined || mark.delegation.expiresAt > now - skew)));
	const verified = chain.trustMarkEvaluations.filter(
		(result) => result.status === "verified" && current(result.mark),
	);
	for (const type of requirements.requiredTypes ?? []) {
		if (!verified.some((result) => result.trustMarkType === type)) {
			return err({
				code: InternalErrorCode.TrustMarkInvalid,
				description: `Required Trust Mark '${type}' is unavailable or invalid`,
			});
		}
	}
	if (requirements.requireAllPublished && verified.length !== chain.trustMarkEvaluations.length) {
		return err({
			code: InternalErrorCode.TrustMarkInvalid,
			description:
				"Application policy requires every published Trust Mark to be verified and temporally valid",
		});
	}
	return ok(undefined);
}
