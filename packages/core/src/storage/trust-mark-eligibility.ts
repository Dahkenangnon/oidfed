/** Eligibility checks for stored Trust Marks, including expiry and local revocation. */

import { parseCompactJws } from "@oidfed/crypto";
import { JwtTyp } from "../constants.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { TrustMarkDelegationPayloadSchema } from "../schemas/trust-mark.js";
import type { StorageValidationOptions } from "./record-schemas.js";
import type { TrustMarkRecord } from "./trust-mark.js";

/** Read signed JWT syntax without verifying the signature or invoking a profile callback. */
export function readStoredSignedJwt(jwt: string, options?: StorageValidationOptions) {
	try {
		const parsed = parseCompactJws(jwt, {
			...(options?.maxCompactBytes === undefined ? {} : { maxBytes: options.maxCompactBytes }),
			...(options?.algorithmRegistry === undefined
				? {}
				: { algorithmRegistry: options.algorithmRegistry }),
		});
		return parsed.header.kid && parsed.header.typ ? parsed : undefined;
	} catch {
		return undefined;
	}
}

export function readStoredDelegation(jwt: string, options?: StorageValidationOptions) {
	const decoded = readStoredSignedJwt(jwt, options);
	if (decoded?.header.typ !== JwtTyp.TrustMarkDelegation) return undefined;
	const parsed = TrustMarkDelegationPayloadSchema.safeParse(decoded.payload);
	return parsed.success ? parsed.data : undefined;
}

/** Apply exact issuer time and local revocation to a previously verified Trust Mark. */
export function isStoredTrustMarkEligible(
	record: TrustMarkRecord,
	validAt: number,
	validation?: number | StorageValidationOptions,
): boolean {
	if (
		!Number.isFinite(validAt) ||
		!record.active ||
		record.revokedAt !== undefined ||
		!Number.isFinite(record.issuedAt) ||
		record.issuedAt > validAt ||
		(record.expiresAt !== undefined &&
			(!Number.isFinite(record.expiresAt) || record.expiresAt <= validAt))
	)
		return false;
	const options = typeof validation === "number" ? { maxCompactBytes: validation } : validation;
	const decoded = decodeEntityStatement(record.jwt, options);
	if (!decoded.ok) return false;
	const token = decoded.value.payload.delegation;
	if (token === undefined) return true;
	if (typeof token !== "string") return false;
	const delegation = readStoredDelegation(token, options);
	return (
		!!delegation &&
		delegation.sub === decoded.value.payload.iss &&
		delegation.trust_mark_type === record.trustMarkType &&
		delegation.iat <= validAt &&
		(delegation.exp === undefined || delegation.exp > validAt)
	);
}
