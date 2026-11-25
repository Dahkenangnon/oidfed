import { assertPublicJwk, DEFAULT_JWS_REGISTRY } from "@oidfed/crypto";
/** Validation and preparation of public verification-key material. */

import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { type JWK, type JWKSet, JWKSetSchema, MetadataJWKSetSchema } from "../schemas/jwk.js";

const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const EC_LENGTHS = new Map([
	["P-256", 32],
	["P-384", 48],
	["P-521", 66],
]);
const OKP_LENGTHS = new Map([
	["Ed25519", 32],
	["Ed448", 57],
	["X25519", 32],
	["X448", 56],
]);

/**
 * Check the JSON representation before publishing a federation JWK Set. Includes the
 * federation schema's unique, nonempty kid requirement. RFC 7518 §6 and RFC 8037
 * §2 define the public parameters; key import and cryptographic operations
 * establish whether the key is usable with the chosen backend and algorithm.
 *
 * Received sets use the existing schemas and verification-key selection:
 * RFC 7517 §5 recommends ignoring unusable keys when consuming a set.
 */
export function validatePublicJwkSet(
	value: unknown,
	registry = DEFAULT_JWS_REGISTRY,
): Result<void, FederationError> {
	const prepared = preparePublicJwkSet(value, registry);
	return prepared.ok ? ok(undefined) : prepared;
}

/** Capture the JSON data once so publishers store and sign exactly what was validated. */
export function preparePublicJwkSet(
	value: unknown,
	registry = DEFAULT_JWS_REGISTRY,
): Result<JWKSet, FederationError> {
	return prepareKeySet(value, registry, JWKSetSchema);
}

/** Prepare public protocol keys without imposing the Federation signing key identifier rules. */
export function prepareProtocolJwkSet(
	value: unknown,
	registry = DEFAULT_JWS_REGISTRY,
): Result<JWKSet, FederationError> {
	return prepareKeySet(value, registry, MetadataJWKSetSchema);
}

function prepareKeySet(
	value: unknown,
	registry: typeof DEFAULT_JWS_REGISTRY,
	schema: typeof MetadataJWKSetSchema,
): Result<JWKSet, FederationError> {
	let snapshot: unknown;
	try {
		const json = JSON.stringify(value);
		if (json === undefined) return invalid("jwks", "expected a JSON object");
		snapshot = JSON.parse(json);
	} catch {
		return invalid("jwks", "could not serialize public JWK Set");
	}
	const parsed = schema.safeParse(snapshot);
	if (!parsed.success) {
		const path = parsed.error.issues[0]?.path
			.map((part) => (typeof part === "number" ? `[${part}]` : `.${String(part)}`))
			.join("")
			.replace(/^\./, "");
		return invalid(path || "jwks", "invalid public JWK Set structure");
	}
	const keys = [...(snapshot as JWKSet).keys];
	for (const [index, key] of keys.entries()) {
		if (!registry.keyType(key.kty))
			return invalid(`keys[${index}].kty`, "unsupported public key type");
		if (DEFAULT_JWS_REGISTRY.keyType(key.kty)) {
			const check = validateMaterial(key, `keys[${index}]`);
			if (!check.ok) return check;
		} else {
			try {
				keys[index] = assertPublicJwk(key, registry);
			} catch {
				return invalid(`keys[${index}]`, "invalid registered public key material");
			}
		}
	}
	return ok({ ...(snapshot as JWKSet), keys });
}

function validateMaterial(key: JWK, path: string): Result<void, FederationError> {
	if (key.kty === "RSA") {
		for (const field of ["n", "e"] as const) {
			const value = key[field];
			const length = encodedLength(value);
			if (length === undefined) return invalid(`${path}.${field}`, "expected nonempty base64url");
			// Base64urlUInt uses the minimum octets (RFC 7518 §2 and §6.3.1).
			if (
				length > 1 &&
				value &&
				BASE64URL.indexOf(value.charAt(0)) === 0 &&
				BASE64URL.indexOf(value.charAt(1)) < 16
			) {
				return invalid(`${path}.${field}`, "unsigned integer has a leading zero octet");
			}
		}
		return ok(undefined);
	}
	if (!key.crv) return invalid(`${path}.crv`, "expected a nonempty curve identifier");
	const length = (key.kty === "EC" ? EC_LENGTHS : OKP_LENGTHS).get(key.crv);
	const fields: ("x" | "y")[] = ["x"];
	// Future EC curves define their own representation; only these curves require y here.
	if (key.kty === "EC" && (length !== undefined || key.y !== undefined)) fields.push("y");
	for (const field of fields) {
		const actual = encodedLength(key[field]);
		if (actual === undefined) return invalid(`${path}.${field}`, "expected nonempty base64url");
		if (length !== undefined && actual !== length) {
			return invalid(`${path}.${field}`, `expected ${length} octets for this curve`);
		}
	}
	return ok(undefined);
}

/** Check the alphabet, unpadded length and unused bits without decoding or allocating bytes. */
function encodedLength(value: string | undefined): number | undefined {
	if (!value || /[^A-Za-z0-9_-]/.test(value)) return undefined;
	const remainder = value.length % 4;
	if (remainder === 1) return undefined;
	const last = BASE64URL.indexOf(value.charAt(value.length - 1));
	if ((remainder === 2 && (last & 15) !== 0) || (remainder === 3 && (last & 3) !== 0)) {
		return undefined;
	}
	return Math.floor((value.length * 6) / 8);
}

function invalid(path: string, reason: string): Result<never, FederationError> {
	return err(federationError(FederationErrorCode.InvalidMetadata, `Invalid ${path}: ${reason}`));
}
