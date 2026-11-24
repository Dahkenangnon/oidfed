import type { FederationArtifact } from "@oidfed/crypto";
import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { Clock, FederationOptions } from "../types.js";

export function apiError(description: string): FederationError {
	return { code: InternalErrorCode.SignatureInvalid, description };
}

export interface VerifyOptions extends FederationOptions {
	/** Expected signer identity from trusted configuration or validated federation evidence. */
	expectedIssuer: string;
	clockSkewSeconds?: number;
	clock?: Clock;
}

/** Validate caller context before accepting any signed response (RFC 8725 §3.8). */
export function validateExpectedIssuer(options: VerifyOptions): Result<void, FederationError> {
	return EntityIdSchema.safeParse(options?.expectedIssuer).success
		? ok(undefined)
		: err(apiError("A valid expectedIssuer is required"));
}

export function buildVerifyOpts(
	expectedTyp: string,
	options: VerifyOptions,
	artifact: FederationArtifact,
) {
	return { ...options, expectedTyp, artifact };
}
