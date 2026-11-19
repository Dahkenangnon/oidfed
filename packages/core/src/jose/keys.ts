/** Asymmetric key generation, public JWK handling, and verification-key selection. */

import {
	type CryptoEngine,
	DEFAULT_JWS_REGISTRY,
	encodeBase64url,
	jwkThumbprint as thumbprint,
	utf8Encode,
} from "@oidfed/crypto";
import type { JWK, JWKSet } from "../schemas/jwk.js";

/** Returns true if the given value is a supported asymmetric signing algorithm (not "none"). */
export function isValidAlgorithm(alg: unknown, registry = DEFAULT_JWS_REGISTRY): alg is string {
	return typeof alg === "string" && registry.algorithm(alg) !== undefined;
}

/** Compute the RFC 7638 SHA-256 thumbprint using the supplied engine. */
export async function jwkThumbprint(
	key: JWK,
	engine: CryptoEngine,
	registry = DEFAULT_JWS_REGISTRY,
): Promise<string> {
	return encodeBase64url(await thumbprint(engine, key, registry));
}

/** Select the best verification key from a JWKS, matching by `kid` first then by algorithm. */
export function selectVerificationKey(
	header: { kid?: string; alg?: string },
	jwks: JWKSet,
	registry = DEFAULT_JWS_REGISTRY,
): JWK | undefined {
	// Keep the original set intact; unsupported types are ineligible candidates (RFC 7517 §5).
	const keys = jwks.keys.filter(
		(key) =>
			registry.keyType(key.kty) !== undefined &&
			(key.key_ops === undefined || key.key_ops.includes("verify")),
	);

	if (header.kid) {
		const byKid = keys.find((k) => k.kid === header.kid && (!k.use || k.use === "sig"));
		if (byKid?.alg && header.alg && byKid.alg !== header.alg) {
			return undefined; // Skip keys whose declared algorithm differs from the JWT algorithm.
		}
		return byKid;
	}

	if (header.alg) {
		const expectedKty = registry.algorithm(header.alg)?.keyType;
		if (expectedKty) {
			const byAlg = keys.find(
				(k) =>
					k.kty === expectedKty && (!k.use || k.use === "sig") && (!k.alg || k.alg === header.alg),
			);
			if (byAlg) return byAlg;
		}
	}

	return undefined;
}

export function timingSafeEqual(a: string, b: string): boolean {
	const bufA = utf8Encode(a);
	const bufB = utf8Encode(b);
	// Length mismatch leaks that lengths differ; acceptable because values
	// being compared (entity IDs, client_id) are public HTTPS URLs.
	if (bufA.length !== bufB.length) return false;
	let diff = 0;
	for (let i = 0; i < bufA.length; i++) {
		diff |= (bufA[i] ?? 0) ^ (bufB[i] ?? 0);
	}
	return diff === 0;
}

/** Allowlist of JWK fields that are safe to expose publicly. */
export const JWK_PUBLIC_FIELDS: ReadonlySet<string> = new Set([
	"kty",
	"use",
	"key_ops",
	"alg",
	"kid",
	"x5u",
	"x5c",
	"x5t",
	"x5t#S256",
	"crv",
	"x",
	"y",
	"n",
	"e",
]);

/**
 * Strip private key material from a JWK, returning only spec-defined public fields.
 *
 * Uses an allowlist strategy so that unknown or future private parameters are excluded by default.
 *
 * Throws TypeError for symmetric keys (kty "oct") which have no public representation.
 */
export function stripPrivateFields(key: JWK): JWK {
	const raw = key as Record<string, unknown>;
	if (raw.kty === "oct") {
		throw new TypeError(
			'Cannot extract public fields from a symmetric key (kty "oct"): the entire key value is private',
		);
	}
	const pub: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(raw)) {
		if (JWK_PUBLIC_FIELDS.has(k)) {
			pub[k] = v;
		}
	}
	return pub as unknown as JWK;
}
