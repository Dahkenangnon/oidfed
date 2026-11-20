import { assertPublicJwk, DEFAULT_JWS_REGISTRY, type JwsAlgorithmRegistry } from "@oidfed/crypto";
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

export type JWK = import("@oidfed/crypto").Jwk;
export type JWKSet = { readonly keys: readonly JWK[] };

/** Options for validating protocol metadata containing inline JWK Sets. */
export interface MetadataValidationOptions {
	readonly algorithmRegistry?: JwsAlgorithmRegistry | undefined;
}

/** Check the conditional JWK `use` rule after parsing the metadata structure. */
export function withMetadataJwkUse<T extends z.ZodType>(
	schema: T,
	{ algorithmRegistry }: MetadataValidationOptions = {},
) {
	return schema.superRefine((meta, ctx) => {
		if (!meta || typeof meta !== "object" || !("jwks" in meta)) return;
		const keys = MetadataJWKSetSchema.safeParse(meta.jwks);
		if (!keys.success) return;
		const use = validateJwkSetUseRequirement(keys.data.keys, algorithmRegistry);
		if (!use.ok) ctx.addIssue({ code: "custom", path: ["jwks"], message: use.error.description });
	});
}

/** Validate inline protocol sets before publishing composed host metadata. */
export function validatePublishedMetadataKeys(
	metadata: Readonly<Record<string, unknown>>,
	registry = DEFAULT_JWS_REGISTRY,
): void {
	for (const block of Object.values(metadata)) {
		if (!block || typeof block !== "object" || Array.isArray(block)) continue;
		const jwks = (block as Record<string, unknown>).jwks;
		if (jwks === undefined) continue;
		const parsed = MetadataJWKSetSchema.safeParse(jwks);
		if (!parsed.success || !parsed.data.keys.every((key) => registry.keyType(key.kty)))
			throw new Error("Published metadata must contain supported public JWKs");
		for (const key of parsed.data.keys) {
			if (DEFAULT_JWS_REGISTRY.keyType(key.kty)) continue;
			const approved = assertPublicJwk(key, registry);
			if (Object.keys(key).some((name) => !Object.hasOwn(approved, name)))
				throw new TypeError("Registered protocol keys must contain only approved public fields");
		}
		const use = validateJwkSetUseRequirement(parsed.data.keys, registry);
		if (!use.ok) throw new Error(use.error.description);
	}
}
