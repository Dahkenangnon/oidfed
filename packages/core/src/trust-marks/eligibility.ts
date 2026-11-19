/** Eligibility checks for stored Trust Marks, including expiry and local revocation. */

import { DEFAULT_MAX_COMPACT_JWS_BYTES } from "@oidfed/crypto";
import { decodeEntityStatement } from "../jose/verify.js";
import type { TrustMarkRecord } from "./storage.js";

/**
 * Filter previously verified stored marks by active state and mark/delegation time.
 * Apply before choosing the newest record, using exact issuer time without leeway.
 * Ingestion must establish signature, issuer trust, and matching record fields;
 * this predicate does not perform cryptographic or profile verification.
 */
export function isStoredTrustMarkEligible(
	record: TrustMarkRecord,
	validAt: number,
	maxCompactBytes = DEFAULT_MAX_COMPACT_JWS_BYTES,
): boolean {
	if (
		!Number.isSafeInteger(maxCompactBytes) ||
		maxCompactBytes <= 0 ||
		record.jwt.length > maxCompactBytes
	)
		return false;
	const decoded = decodeEntityStatement(record.jwt, { maxCompactBytes });
	if (decoded.ok && decoded.value.payload.delegation !== undefined) {
		const delegation = decodeEntityStatement(decoded.value.payload.delegation as string, {
			maxCompactBytes,
		});
		if (
			!delegation.ok ||
			!Number.isFinite(delegation.value.payload.iat) ||
			delegation.value.payload.iat > validAt ||
			(delegation.value.payload.exp !== undefined && delegation.value.payload.exp <= validAt)
		)
			return false;
	}
	// Federation §7.3: select currently eligible marks before choosing the newest.
	// Authority storage uses its exact clock, including same-second issuance.
	return (
		record.active &&
		Number.isFinite(record.issuedAt) &&
		record.issuedAt <= validAt &&
		(record.expiresAt === undefined || record.expiresAt > validAt)
	);
}
