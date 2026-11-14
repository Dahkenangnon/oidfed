/** Structural schemas for public JSON Web Keys and federation JWK Sets. */
import { z } from "zod";
import { validateJwkSetUseRequirement } from "../jwks/use-requirement.js";

const PRIVATE_KEY_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

export const JWKSchema = z
	.looseObject({
		// RFC 7517 §5: received sets may include key types this implementation cannot use.
		kty: z.string().min(1),
		kid: z.string().min(1).optional(),
		use: z.string().optional(),
		alg: z.string().optional(),
		key_ops: z.array(z.string()).optional(),
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

/** Public protocol keys under Federation §5.2.1 and RFC 7517 §4.5. */
export const MetadataJWKSetSchema = z.object({
	keys: z.array(JWKSchema),
});

/** Federation signing keys require distinct, nonempty identifiers (§3.1.1). */
export const JWKSetSchema = MetadataJWKSetSchema.extend({
	keys: MetadataJWKSetSchema.shape.keys.min(1),
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

/** Supported publication shape; received sets retain unknown key types for selection. */
export const PublicationJWKSchema = JWKSchema.refine(
	(key) => ["RSA", "EC", "OKP"].includes(key.kty),
	{ message: "Unsupported public key type for publication" },
);

/** Validate inline protocol sets before publishing composed host metadata. */
export function validatePublishedMetadataKeys(metadata: Readonly<Record<string, unknown>>): void {
	for (const block of Object.values(metadata)) {
		if (!block || typeof block !== "object" || Array.isArray(block)) continue;
		const jwks = (block as Record<string, unknown>).jwks;
		if (jwks === undefined) continue;
		const parsed = MetadataJWKSetSchema.safeParse(jwks);
		if (
			!parsed.success ||
			!parsed.data.keys.every((key) => PublicationJWKSchema.safeParse(key).success)
		)
			throw new Error("Published metadata must contain supported public JWKs");
		const use = validateJwkSetUseRequirement(parsed.data.keys);
		if (!use.ok) throw new Error(use.error.description);
	}
}
