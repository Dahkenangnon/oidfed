/**
 * Require `use` on every key when a JWK Set contains both signing and encryption keys.
 *
 * A key's `use` value of sig or enc determines its purpose. Otherwise, inspect
 * `key_ops` (RFC 7517) and `alg` (RFC 7518). A key whose purpose cannot be inferred
 * does not trigger the rule by itself. A set containing only signing, only encryption,
 * or only ambiguous keys does not trigger it either.
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
 * key are present in the set, but at least one key has no nonempty `use` value.
 * RFC 7517 permits extension values in addition to sig and enc.
 */
export function validateJwkSetUseRequirement(jwks: readonly JWK[]): Result<void, FederationError> {
	if (jwks.length === 0) return ok(undefined);

	const hasSigning = jwks.some(isLikelySigning);
	const hasEncryption = jwks.some(isLikelyEncryption);

	if (!hasSigning || !hasEncryption) {
		return ok(undefined);
	}

	for (const jwk of jwks) {
		if (typeof jwk.use !== "string" || jwk.use.length === 0) {
			const kid = jwk.kid ?? "<no kid>";
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`JWK Set contains both signing and encryption keys; every key MUST carry the 'use' parameter (key '${kid}' has no nonempty 'use' value)`,
				),
			);
		}
	}

	return ok(undefined);
}
