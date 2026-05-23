/** Zod schemas for explicit-registration request and response payloads. */
import {
	EntityIdSchema,
	FederationMetadataSchema,
	JWKSetSchema,
	TrustMarkRefSchema,
} from "@oidfed/core";
import { z } from "zod";

/** Explicit registration request payload. */
export const ExplicitRegistrationRequestPayloadSchema = z
	.looseObject({
		iss: EntityIdSchema,
		sub: EntityIdSchema,
		aud: z.string(),
		iat: z.number().int().positive(),
		exp: z.number().int().positive(),
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
			return meta !== undefined && "openid_relying_party" in meta;
		},
		{
			message: "Explicit registration request metadata MUST contain 'openid_relying_party'",
			path: ["metadata"],
		},
	);

/** Explicit registration response payload. */
export const ExplicitRegistrationResponsePayloadSchema = z
	.looseObject({
		iss: EntityIdSchema,
		sub: EntityIdSchema,
		aud: z.string(),
		iat: z.number().int().positive(),
		exp: z.number().int().positive(),
		metadata: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
		trust_anchor: EntityIdSchema,
		authority_hints: z.array(EntityIdSchema).length(1),
		client_secret: z.string().optional(),
	})
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	});

export type ExplicitRegistrationRequestPayload = z.infer<
	typeof ExplicitRegistrationRequestPayloadSchema
>;
export type ExplicitRegistrationResponsePayload = z.infer<
	typeof ExplicitRegistrationResponsePayloadSchema
>;
