import type { JWKSet } from "../schemas/jwk.js";
import type { EntityId } from "../types.js";

/** Result of comparing Trust Anchor keys from two sources. */
export interface AnchorKeyComparisonResult {
	match: boolean;
	entityId: EntityId;
	ecKids: string[];
	independentKids: string[];
	missingInEc: string[];
	missingInIndependent: string[];
}

/**
 * Compare Trust Anchor public keys retrieved from the Entity Configuration
 * against keys retrieved via an independent mechanism.
 */
export function compareTrustAnchorKeys(
	ecJwks: Pick<JWKSet, "keys">,
	independentJwks: Pick<JWKSet, "keys">,
	entityId: EntityId,
): AnchorKeyComparisonResult {
	const ecKids = ecJwks.keys
		.map((k) => k.kid)
		.filter((kid): kid is string => typeof kid === "string")
		.sort();

	const independentKids = independentJwks.keys
		.map((k) => k.kid)
		.filter((kid): kid is string => typeof kid === "string")
		.sort();

	const ecSet = new Set(ecKids);
	const indSet = new Set(independentKids);

	const missingInEc = independentKids.filter((kid) => !ecSet.has(kid));
	const missingInIndependent = ecKids.filter((kid) => !indSet.has(kid));

	return {
		match: missingInEc.length === 0 && missingInIndependent.length === 0,
		entityId,
		ecKids,
		independentKids,
		missingInEc,
		missingInIndependent,
	};
}
