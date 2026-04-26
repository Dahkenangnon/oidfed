/**
 * Validates the conditional rule that when a JWK Set contains both signing
 * and encryption keys, the `use` parameter is REQUIRED on every key.
 *
 * Capability inference order (most authoritative first):
 *   1. The key's own `use` parameter (sig/enc) — when present, it is dispositive.
 *   2. `key_ops` — RFC 7517 explicit operation list.
 *   3. `alg` — RFC 7518 algorithm family (JWS vs JWE key-management).
 *   4. Otherwise the key is treated as ambiguous (could be either) and does
 *      not by itself trigger the rule.
 *
 * The rule does NOT apply when the set contains only signing-capable keys, or
 * only encryption-capable keys, or only ambiguous keys.
 */
import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import type { JWK } from "../schemas/jwk.js";

/** RFC 7518 JWS signing algorithms. */
const JWS_ALGS: ReadonlySet<string> = new Set([
	"HS256",
	"HS384",
	"HS512",
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384",
	"ES512",
	"ES256K",
	"PS256",
	"PS384",
	"PS512",
	"EdDSA",
]);

/** RFC 7518 JWE key-management algorithms. */
const JWE_ALGS: ReadonlySet<string> = new Set([
	"RSA1_5",
	"RSA-OAEP",
	"RSA-OAEP-256",
	"A128KW",
	"A192KW",
	"A256KW",
	"dir",
	"ECDH-ES",
	"ECDH-ES+A128KW",
	"ECDH-ES+A192KW",
	"ECDH-ES+A256KW",
	"A128GCMKW",
	"A192GCMKW",
	"A256GCMKW",
	"PBES2-HS256+A128KW",
	"PBES2-HS384+A192KW",
	"PBES2-HS512+A256KW",
]);

/** RFC 7517 encryption-side key operations. */
const ENC_KEY_OPS: ReadonlySet<string> = new Set([
	"encrypt",
	"decrypt",
	"wrapKey",
	"unwrapKey",
	"deriveKey",
	"deriveBits",
]);

function isLikelySigning(jwk: JWK): boolean {
	if (jwk.use === "sig") return true;
	if (jwk.use === "enc") return false;
	if (jwk.key_ops?.some((op) => op === "sign" || op === "verify")) return true;
	if (jwk.alg && JWS_ALGS.has(jwk.alg)) return true;
	return false;
}

function isLikelyEncryption(jwk: JWK): boolean {
	if (jwk.use === "enc") return true;
	if (jwk.use === "sig") return false;
	if (jwk.key_ops?.some((op) => ENC_KEY_OPS.has(op))) return true;
	if (jwk.alg && JWE_ALGS.has(jwk.alg)) return true;
	return false;
}

/**
 * Returns ok if the JWK Set satisfies the `use` conditional REQUIRED rule.
 *
 * Returns InvalidMetadata when both a signing-capable and an encryption-capable
 * key are present in the set, but at least one key is missing the `use` member.
 */
export function validateJwkSetUseRequirement(jwks: readonly JWK[]): Result<void, FederationError> {
	if (jwks.length === 0) return ok(undefined);

	const hasSigning = jwks.some(isLikelySigning);
	const hasEncryption = jwks.some(isLikelyEncryption);

	if (!hasSigning || !hasEncryption) {
		return ok(undefined);
	}

	for (const jwk of jwks) {
		if (jwk.use !== "sig" && jwk.use !== "enc") {
			const kid = jwk.kid ?? "<no kid>";
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`JWK Set contains both signing and encryption keys; every key MUST carry the 'use' parameter (key '${kid}' is missing 'use')`,
				),
			);
		}
	}

	return ok(undefined);
}
