import {
	err,
	type FederationError,
	FederationErrorCode,
	federationError,
	ok,
	type RegistrationProtocolAdapter,
	type Result,
	type ValidatedTrustChain,
} from "@oidfed/core";
import { OpenIDRelyingPartyMetadataSchema } from "../schemas/metadata.js";

/**
 * OIDC-specific registration protocol adapter.
 *
 * Validates `openid_relying_party` metadata against the OIDC RP metadata schema
 * and enriches the registration response with `client_id`.
 *
 * Implements the `RegistrationProtocolAdapter` interface from `@oidfed/core`.
 */
export class OIDCRegistrationAdapter implements RegistrationProtocolAdapter {
	validateClientMetadata(
		raw: Record<string, unknown>,
	): Result<Record<string, unknown>, FederationError> {
		const rpMeta = raw.openid_relying_party;
		if (!rpMeta || typeof rpMeta !== "object") {
			// Intentional pass-through: non-RP entities (e.g. AS, OP) may not carry
			// openid_relying_party metadata. The OP-side process-explicit handler
			// enforces its presence before this adapter is invoked (SEC-2).
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
