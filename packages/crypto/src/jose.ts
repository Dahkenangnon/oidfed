import { assertEcPublicPoint } from "./ec-public-key.js";
/** Optional JOSE v6 integration; only this subpath imports jose. */

import {
	assertVerificationKey,
	type CryptoEngine,
	CryptoError,
	CryptoUnsupportedError,
	encodeBase64url,
	jwsSignatureRules,
	toPublicJwk,
} from "@oidfed/crypto";
import {
	createWebCryptoEngine,
	type WebCryptoEngineOptions,
	type WebCryptoLike,
} from "@oidfed/crypto/web";
import { compactVerify, errors, importJWK } from "jose";

/** Create the optional JOSE verification backend.
 * JOSE uses global Web Crypto for verification. An injected implementation supplies
 * digest and randomness only. Use the Web adapter or a custom engine for full injection.
 * @throws {CryptoError} UNSUPPORTED_RUNTIME if digest/random have no Web Crypto implementation.
 * @throws {CryptoUnsupportedError} If the configured capability list is invalid.
 */
export function createJoseEngine<Key = unknown>(
	implementation?: WebCryptoLike<Key>,
	options?: WebCryptoEngineOptions,
): CryptoEngine {
	const base = createWebCryptoEngine(implementation, options);
	return Object.freeze({
		...base,
		async validatePublicKey(key, algorithm) {
			if (!base.algorithms.includes(algorithm))
				throw new CryptoUnsupportedError(`Engine does not support ${algorithm}`);
			assertVerificationKey(key, algorithm);
			assertEcPublicPoint(key);
			try {
				await importJWK(toJoseKey(key), algorithm);
			} catch (cause) {
				if (
					cause instanceof errors.JOSENotSupported ||
					(cause instanceof Error && cause.name === "NotSupportedError")
				)
					throw new CryptoUnsupportedError("JOSE cannot import this key", { cause });
				if (
					cause instanceof errors.JWKInvalid ||
					(cause instanceof Error && ["DataError", "SyntaxError"].includes(cause.name))
				)
					throw new CryptoError("MALFORMED_KEY", "JOSE rejected public key material", { cause });
				throw new CryptoError("CRYPTO_OPERATION_FAILED", "JOSE key validation failed", { cause });
			}
		},
		async verify({ algorithm, key, signingInput, signature }) {
			if (!base.algorithms.includes(algorithm))
				throw new CryptoUnsupportedError(`Engine does not support ${algorithm}`);
			assertVerificationKey(key, algorithm);
			if (signature instanceof Uint8Array && !jwsSignatureRules(key, algorithm).accepts(signature))
				return false;
			assertEcPublicPoint(key);
			if (!(signingInput instanceof Uint8Array) || !(signature instanceof Uint8Array))
				throw new CryptoError("MALFORMED_JWS", "Verification requires byte inputs");
			let encodedInput = "";
			for (const byte of signingInput) {
				if (byte > 0x7f) throw new CryptoError("MALFORMED_JWS", "JWS signing input must be ASCII");
				encodedInput += String.fromCharCode(byte);
			}
			const compact = `${encodedInput}.${encodeBase64url(signature)}`;
			try {
				const imported = await importJWK(toJoseKey(key), algorithm);
				await compactVerify(compact, imported, { algorithms: [algorithm] });
				return true;
			} catch (cause) {
				if (
					cause instanceof errors.JWSSignatureVerificationFailed ||
					cause instanceof errors.JWSInvalid
				)
					return false;
				if (
					cause instanceof errors.JOSENotSupported ||
					(cause instanceof Error && cause.name === "NotSupportedError")
				)
					throw new CryptoUnsupportedError("JOSE cannot perform this operation", { cause });
				throw new CryptoError("CRYPTO_OPERATION_FAILED", "JOSE verification failed", { cause });
			}
		},
	} satisfies CryptoEngine);
}

function toJoseKey(
	key: Parameters<CryptoEngine["verify"]>[0]["key"],
): Parameters<typeof importJWK>[0] {
	const result: Parameters<typeof importJWK>[0] = { kty: key.kty };
	for (const [name, value] of Object.entries(toPublicJwk(key)))
		if (value !== undefined)
			Object.defineProperty(result, name, {
				value: Array.isArray(value) ? Array.from(value as readonly unknown[]) : value,
				enumerable: true,
			});
	return result;
}
