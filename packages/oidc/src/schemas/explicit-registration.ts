/** Zod schemas for explicit-registration request and response payloads. */
import {
	EntityIdSchema,
	FederationMetadataSchema,
	JWKSetSchema,
	TrustMarkRefSchema,
} from "@oidfed/core";
import { z } from "zod";
import { OpenIDRelyingPartyRegistrationResponseMetadataSchema } from "./metadata.js";

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

const ExplicitRegistrationResponseMetadataSchema = z
	.record(z.string(), z.record(z.string(), z.unknown()))
	.superRefine((metadata, ctx) => {
		const result = OpenIDRelyingPartyRegistrationResponseMetadataSchema.safeParse(
			metadata.openid_relying_party,
		);
		if (!result.success) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "metadata.openid_relying_party must be valid registration response metadata",
				path: ["openid_relying_party"],
			});
		}
	});

/** Explicit registration response payload. */
export const ExplicitRegistrationResponsePayloadSchema = z
	.looseObject({
		iss: EntityIdSchema,
		sub: EntityIdSchema,
		aud: z.string(),
		iat: z.number().int().positive(),
		exp: z.number().int().positive(),
		metadata: ExplicitRegistrationResponseMetadataSchema,
		trust_anchor: EntityIdSchema,
		authority_hints: z.array(EntityIdSchema).length(1),
	})
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	})
	.refine((obj) => !("client_secret" in obj), {
		message: "client_secret MUST be nested under metadata.openid_relying_party",
		path: ["client_secret"],
	});

export type ExplicitRegistrationRequestPayload = z.infer<
	typeof ExplicitRegistrationRequestPayloadSchema
>;
export type ExplicitRegistrationResponsePayload = z.infer<
	typeof ExplicitRegistrationResponsePayloadSchema
>;
