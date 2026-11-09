import { jwkThumbprint } from "../jose/keys.js";
import { preparePublicJwkSet } from "../jwks/public-material.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { EntityId } from "../types.js";

/** Result of comparing Trust Anchor keys from two sources. */
export interface TrustAnchorKeyComparisonResult {
	match: boolean;
	entityId: EntityId;
	missingInEntityConfiguration: string[];
	missingInIndependentSource: string[];
	mismatchedKeyMaterial: string[];
	/** Sources whose complete public key sets could not be compared. */
	inputErrors?: readonly {
		source: "entity_configuration" | "independent_source";
		reason: string;
	}[];
}

/**
 * Compare Trust Anchor public keys retrieved from the Entity Configuration
 * against keys retrieved via an independent mechanism.
 */
export async function compareTrustAnchorKeys(
	ecJwks: Pick<JWKSet, "keys">,
	independentJwks: Pick<JWKSet, "keys">,
	entityId: EntityId,
): Promise<TrustAnchorKeyComparisonResult> {
	const inputErrors: NonNullable<TrustAnchorKeyComparisonResult["inputErrors"]>[number][] = [];
	// §11.3 compares complete sets. Silently skipping a key can create false agreement.
	const index = async (
		jwks: Pick<JWKSet, "keys">,
		source: "entity_configuration" | "independent_source",
	) => {
		const keys = new Map<string, string>();
		const prepared = preparePublicJwkSet(jwks);
		if (!prepared.ok) {
			inputErrors.push({ source, reason: prepared.error.description });
			return keys;
		}
		for (const key of prepared.value.keys) {
			try {
				keys.set(key.kid as string, await jwkThumbprint(key));
			} catch {
				inputErrors.push({ source, reason: "Could not compute a public key thumbprint" });
			}
		}
		return keys;
	};
	const ecKeys = await index(ecJwks, "entity_configuration");
	const independentKeys = await index(independentJwks, "independent_source");
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
		if (ecKey !== independentKey) {
			mismatchedKeyMaterial.push(kid);
		}
	}

	return {
		match:
			inputErrors.length === 0 &&
			missingInEntityConfiguration.length === 0 &&
			missingInIndependentSource.length === 0 &&
			mismatchedKeyMaterial.length === 0,
		entityId,
		missingInEntityConfiguration,
		missingInIndependentSource,
		mismatchedKeyMaterial,
		...(inputErrors.length > 0 ? { inputErrors } : {}),
	};
}
