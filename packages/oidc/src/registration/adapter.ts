/** Default protocol metadata validation and explicit registration response enrichment. */

import {
	err,
	type FederationError,
	FederationErrorCode,
	federationError,
	ok,
	type Result,
	type ValidatedTrustChain,
} from "@oidfed/core";
import { OpenIDRelyingPartyMetadataSchema } from "../schemas/metadata.js";
import type { RegistrationProtocolAdapter } from "./adapter-types.js";

/**
 * OIDC-specific registration protocol adapter.
 *
 * Validates `openid_relying_party` metadata against the OIDC RP metadata schema
 * and enriches the registration response with `client_id`.
 *
 * Implements the `RegistrationProtocolAdapter` interface from `./adapter-types.js`.
 */
export class OIDCRegistrationAdapter implements RegistrationProtocolAdapter {
	/** Validate openid_relying_party metadata when present; leave other entity metadata unchanged. */
	validateClientMetadata(
		raw: Record<string, unknown>,
	): Result<Record<string, unknown>, FederationError> {
		const rpMeta = raw.openid_relying_party;
		if (!rpMeta || typeof rpMeta !== "object") {
			// This adapter checks openid_relying_party metadata when present.
			// The registration handler requires its profile's client metadata
			// before calling the adapter.
			return ok(raw);
		}

		const parsed = OpenIDRelyingPartyMetadataSchema.safeParse(rpMeta);
		if (!parsed.success) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`Invalid openid_relying_party metadata: ${parsed.error.message}`,
				),
			);
		}

		return ok(raw);
	}

	/**
	 * Copy client metadata and supply client_id from the validated chain when it is absent.
	 */
	enrichResponseMetadata(
		rpMeta: Record<string, unknown>,
		trustChain: ValidatedTrustChain,
	): Record<string, unknown> {
		const enriched = { ...rpMeta };
		if (!enriched.client_id) {
			enriched.client_id = trustChain.entityId;
		}
		return enriched;
	}
}
