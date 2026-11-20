/** Zod schemas for explicit-registration request and response payloads. */

import {
	EntityIdSchema,
	FederationMetadataSchema,
	JWKSetSchema,
	type MetadataValidationOptions,
	TrustMarkRefSchema,
	withMetadataJwkUse,
} from "@oidfed/core";
import { z } from "zod";
import {
	OAuthClientRegistrationResponseMetadataSchema,
	OpenIDRelyingPartyRegistrationResponseMetadataSchema,
} from "./metadata.js";

/** Federation §12 uses the same envelope with the selected protocol's metadata. */
function registrationSchemas(clientType: "openid_relying_party" | "oauth_client") {
	const responseMetadataSchema =
		clientType === "openid_relying_party"
			? OpenIDRelyingPartyRegistrationResponseMetadataSchema
			: OAuthClientRegistrationResponseMetadataSchema;
	/** Explicit registration request payload. */
	const request = z
		.looseObject({
			iss: EntityIdSchema,
			sub: EntityIdSchema,
			aud: z.string(),
			iat: z.number().finite(),
			exp: z.number().finite(),
			jwks: JWKSetSchema,
			authority_hints: z.array(EntityIdSchema).min(1),
			metadata: FederationMetadataSchema,
			trust_marks: z.array(TrustMarkRefSchema).optional(),
		})
		.refine((obj) => obj.exp > obj.iat, {
			message: "exp must be after iat",
			path: ["exp"],
		})
		.refine((obj) => obj.iss === obj.sub, {
			message: "Registration request must be self-signed (iss === sub)",
		})
		.refine(
			(obj) => {
				const meta = obj.metadata as Record<string, unknown> | undefined;
				return meta !== undefined && Object.hasOwn(meta, clientType);
			},
			{
				message: `Explicit registration request metadata MUST contain '${clientType}'`,
				path: ["metadata"],
			},
		);

	const responseFor = (options?: MetadataValidationOptions) => {
		const roleMetadata = withMetadataJwkUse(responseMetadataSchema, options);
		const ExplicitRegistrationResponseMetadataSchema = z
			.record(z.string(), z.record(z.string(), z.unknown()))
			.superRefine((metadata, ctx) => {
				const result = roleMetadata.safeParse(metadata[clientType]);
				if (!result.success) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: `${clientType} must be valid registration response metadata`,
						path: [clientType],
					});
				}
			});

		/** Explicit registration response payload. */
		return z
			.looseObject({
				iss: EntityIdSchema,
				sub: EntityIdSchema,
				aud: z.string(),
				iat: z.number().finite(),
				exp: z.number().finite(),
				metadata: ExplicitRegistrationResponseMetadataSchema,
				trust_anchor: EntityIdSchema,
				authority_hints: z.array(EntityIdSchema).length(1),
			})
			.refine((obj) => obj.exp > obj.iat, {
				message: "exp must be after iat",
				path: ["exp"],
			})
			.refine((obj) => !("client_secret" in obj), {
				message: `client_secret MUST be nested under metadata.${clientType}`,
				path: ["client_secret"],
			})
			.superRefine((obj, ctx) => {
				const rpMetadata = obj.metadata[clientType] as Record<string, unknown> | undefined;
				if (
					typeof rpMetadata?.client_secret === "string" &&
					typeof rpMetadata.client_secret_expires_at === "number" &&
					rpMetadata.client_secret_expires_at !== 0 &&
					rpMetadata.client_secret_expires_at < obj.exp
				) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "client_secret_expires_at must not be earlier than exp",
						path: ["metadata", clientType, "client_secret_expires_at"],
					});
				}
			});
	};
	return { request, response: responseFor(), responseFor };
}
export const oidcRegistrationSchemas = registrationSchemas("openid_relying_party");
export const oauthRegistrationSchemas = registrationSchemas("oauth_client");

export type ExplicitRegistrationRequestPayload = z.infer<typeof oidcRegistrationSchemas.request>;
export type ExplicitRegistrationResponsePayload = z.infer<typeof oidcRegistrationSchemas.response>;
