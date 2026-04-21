/** Zod schemas for JSON Web Keys and JWK Sets, with algorithm-specific field validation. */
import { z } from "zod";

const PRIVATE_KEY_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

export const JWKSchema = z
	.looseObject({
		kty: z.enum(["RSA", "EC", "OKP"]),
		kid: z.string().min(1).optional(),
		use: z.enum(["sig", "enc"]).optional(),
		alg: z.string().optional(),
		key_ops: z
			.array(
				z.enum([
					"sign",
					"verify",
					"encrypt",
					"decrypt",
					"wrapKey",
					"unwrapKey",
					"deriveKey",
					"deriveBits",
				]),
			)
			.optional(),
		// RSA public parameters
		n: z.string().optional(),
		e: z.string().optional(),
		// EC / OKP parameters
		crv: z.string().optional(),
		x: z.string().optional(),
		y: z.string().optional(),
	})
	.superRefine((jwk, ctx) => {
		// JWKS MUST represent the public part only
		for (const f of PRIVATE_KEY_FIELDS) {
			if (f in (jwk as Record<string, unknown>)) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `JWK must not contain private key material (field: "${f}")`,
				});
			}
		}
	});

export const JWKSetSchema = z
	.object({
		keys: z.array(JWKSchema).min(1),
	})
	.refine((jwks) => jwks.keys.every((k) => typeof k.kid === "string" && k.kid.length > 0), {
		message: "Every JWK in the set MUST have a non-empty kid",
		path: ["keys"],
	})
	.refine(
		(jwks) => {
			const kids = jwks.keys.map((k) => k.kid).filter(Boolean);
			return new Set(kids).size === kids.length;
		},
		{ message: "Every JWK kid MUST be unique within the set", path: ["keys"] },
	);

export type JWK = z.infer<typeof JWKSchema>;
export type JWKSet = z.infer<typeof JWKSetSchema>;
