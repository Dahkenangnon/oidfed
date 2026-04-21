/** Key generation and JWK-to-KeyLike conversion utilities using the jose library. */
import * as jose from "jose";
import type { SupportedAlgorithm } from "../constants.js";
import { SUPPORTED_ALGORITHMS } from "../constants.js";
import type { JWK, JWKSet } from "../schemas/jwk.js";

/** Returns true if the given value is a supported asymmetric signing algorithm (not "none"). */
export function isValidAlgorithm(alg: unknown): alg is string {
	return (
		typeof alg === "string" &&
		alg !== "none" &&
		(SUPPORTED_ALGORITHMS as readonly string[]).includes(alg)
	);
}

const ALG_TO_KTY: Record<string, string> = {
	ES256: "EC",
	ES384: "EC",
	ES512: "EC",
	PS256: "RSA",
	PS384: "RSA",
	PS512: "RSA",
	RS256: "RSA",
};

/** Generate an asymmetric signing key pair for the given algorithm. */
export async function generateSigningKey(
	alg: SupportedAlgorithm = "ES256",
): Promise<{ publicKey: JWK; privateKey: JWK }> {
	const { publicKey, privateKey } = await jose.generateKeyPair(alg, {
		extractable: true,
	});
	const pub = await jose.exportJWK(publicKey);
	const priv = await jose.exportJWK(privateKey);
	const kid = await jose.calculateJwkThumbprint(pub);
	return {
		publicKey: { ...pub, kid, alg, use: "sig" } as unknown as JWK,
		privateKey: { ...priv, kid, alg, use: "sig" } as unknown as JWK,
	};
}

/** Compute JWK thumbprint (SHA-256) for the given key. */
export async function jwkThumbprint(key: JWK): Promise<string> {
	return jose.calculateJwkThumbprint(
		key as Parameters<typeof jose.calculateJwkThumbprint>[0],
		"sha256",
	);
}

/** Select the best verification key from a JWKS, matching by `kid` first then by algorithm. */
export function selectVerificationKey(
	header: { kid?: string; alg?: string },
	jwks: JWKSet,
): JWK | undefined {
	const keys = jwks.keys;

	if (header.kid) {
		const byKid = keys.find((k) => k.kid === header.kid && (!k.use || k.use === "sig"));
		if (byKid?.alg && header.alg && byKid.alg !== header.alg) {
			return undefined; // alg mismatch — refuse to return the key
		}
		return byKid;
	}

	if (header.alg) {
		const expectedKty = ALG_TO_KTY[header.alg];
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
	const enc = new TextEncoder();
	const bufA = enc.encode(a);
	const bufB = enc.encode(b);
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
