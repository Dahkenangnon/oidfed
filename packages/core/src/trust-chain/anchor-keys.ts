import { jwkThumbprint } from "../jose/keys.js";
import type { JWK, JWKSet } from "../schemas/jwk.js";
import type { EntityId } from "../types.js";

/** Result of comparing Trust Anchor keys from two sources. */
export interface AnchorKeyComparisonResult {
	match: boolean;
	entityId: EntityId;
	missingInEntityConfiguration: string[];
	missingInIndependentSource: string[];
	mismatchedKeyMaterial: string[];
}

/**
 * Compare Trust Anchor public keys retrieved from the Entity Configuration
 * against keys retrieved via an independent mechanism.
 */
export async function compareTrustAnchorKeys(
	ecJwks: Pick<JWKSet, "keys">,
	independentJwks: Pick<JWKSet, "keys">,
	entityId: EntityId,
): Promise<AnchorKeyComparisonResult> {
	const ecKeys = keysByKid(ecJwks.keys);
	const independentKeys = keysByKid(independentJwks.keys);
	const ecKids = [...ecKeys.keys()].sort();
	const independentKids = [...independentKeys.keys()].sort();

	const ecSet = new Set(ecKids);
	const indSet = new Set(independentKids);

	const missingInEntityConfiguration = independentKids.filter((kid) => !ecSet.has(kid));
	const missingInIndependentSource = ecKids.filter((kid) => !indSet.has(kid));
	const mismatchedKeyMaterial: string[] = [];

	for (const kid of ecKids.filter((value) => indSet.has(value))) {
		const ecKey = ecKeys.get(kid);
		const independentKey = independentKeys.get(kid);
		if (!ecKey || !independentKey) continue;
		const [ecThumbprint, independentThumbprint] = await Promise.all([
			jwkThumbprint(ecKey),
			jwkThumbprint(independentKey),
		]);
		if (ecThumbprint !== independentThumbprint) {
			mismatchedKeyMaterial.push(kid);
		}
	}

	return {
		match:
			missingInEntityConfiguration.length === 0 &&
			missingInIndependentSource.length === 0 &&
			mismatchedKeyMaterial.length === 0,
		entityId,
		missingInEntityConfiguration,
		missingInIndependentSource,
		mismatchedKeyMaterial,
	};
}

function keysByKid(keys: readonly JWK[]): Map<string, JWK> {
	const byKid = new Map<string, JWK>();
	for (const key of keys) {
		if (typeof key.kid === "string" && key.kid.length > 0) {
			byKid.set(key.kid, key);
		}
	}
	return byKid;
}
