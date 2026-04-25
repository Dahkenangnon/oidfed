import type { JWK } from "../../../packages/core/src/schemas/jwk.js";
import type { EntityId, TrustAnchorSet } from "../../../packages/core/src/types.js";

/** Builds a single-entry TrustAnchorSet from a TA entity ID and public key. */
export function createMockTrustAnchors(taId: EntityId, taPublicKey: JWK): TrustAnchorSet {
	return new Map([[taId, { jwks: { keys: [taPublicKey] } }]]);
}
