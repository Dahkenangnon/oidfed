/** Base and application-defined Trust Mark JWT profile validation. */

import { freezeSnapshot } from "../callbacks.js";
import { InternalErrorCode, JwtTyp } from "../constants.js";
import { err, ok, type Result } from "../errors.js";

/** An explicitly recognized framework JWT type, scoped to its Trust Mark types. */
export interface TrustMarkProfile {
	readonly typ: string;
	readonly trustMarkTypes: readonly string[];
	readonly validateClaims?: (
		claims: Readonly<Record<string, unknown>>,
	) => Result<void> | Promise<Result<void>>;
}

/** Apply the base or registered Trust Mark profile and contain profile callback failures. */
export async function checkTrustMarkProfile(
	typ: unknown,
	claims: Record<string, unknown>,
	profiles: readonly TrustMarkProfile[] = [],
	validateClaims = true,
): Promise<Result<void>> {
	const fail = (description: string) =>
		err({ code: InternalErrorCode.TrustMarkInvalid, description });
	try {
		const names = new Set<string>();
		for (const profile of profiles) {
			if (
				!profile ||
				typeof profile.typ !== "string" ||
				!profile.typ ||
				profile.typ === JwtTyp.TrustMark ||
				profile.typ === JwtTyp.TrustMarkDelegation ||
				names.has(profile.typ) ||
				!Array.isArray(profile.trustMarkTypes) ||
				profile.trustMarkTypes.length === 0 ||
				!profile.trustMarkTypes.every((type) => typeof type === "string" && type.length > 0)
			)
				return fail("Invalid or duplicate Trust Mark profile registration");
			names.add(profile.typ);
		}
		if (typ === JwtTyp.TrustMark) return ok(undefined);
		const profile = profiles.find(
			(profile) =>
				profile.typ === typ && profile.trustMarkTypes.includes(claims.trust_mark_type as string),
		);
		if (!profile) return fail("Unrecognized Trust Mark typ or profile/type combination");
		if (!validateClaims || !profile.validateClaims) return ok(undefined);
		const result = await profile.validateClaims(freezeSnapshot(structuredClone(claims)));
		if (!result || typeof result !== "object" || typeof result.ok !== "boolean")
			return fail("Trust Mark profile returned an invalid result");
		if (!result.ok) return fail("Trust Mark profile rejected the claims");
		return ok(undefined);
	} catch {
		return fail("Trust Mark profile validation failed");
	}
}
