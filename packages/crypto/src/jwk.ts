/** Public JWK validation, safe publication, and RFC 7638 thumbprints. */
import { utf8Encode } from "./encoding.js";
import {
	DEFAULT_JWS_REGISTRY,
	isAsymmetricIdentifier,
	JWK_METADATA_MEMBERS,
	type JwsAlgorithmRegistry,
	type JwsSignatureFormat,
	PRIVATE_JWK_MEMBERS,
} from "./registry.js";
import {
	type CryptoEngine,
	CryptoError,
	isJwsAlgorithm,
	type Jwk,
	type PublicJwk,
	type SigningPublicJwk,
} from "./types.js";

function malformed(message: string, cause?: unknown): never {
	throw new CryptoError("MALFORMED_KEY", message, { cause });
}

function metadata(key: Jwk): void {
	for (const name of JWK_METADATA_MEMBERS) {
		const value = key[name];
		if (value === undefined) continue;
		if (name === "key_ops" || name === "x5c") {
			if (!Array.isArray(value) || !Array.from(value).every((item) => typeof item === "string"))
				malformed(`Invalid JWK ${name}`);
		} else if (typeof value !== "string") malformed(`Invalid JWK ${name}`);
	}
}

/** Copy approved public members, omitting private and unknown fields without consulting toJSON. */
export function toPublicJwk(key: Jwk, registry = DEFAULT_JWS_REGISTRY): PublicJwk {
	if (!key || typeof key !== "object" || !Object.hasOwn(key, "kty"))
		malformed("Expected an asymmetric JWK");
	const definition = registry.keyType(key.kty);
	if (!definition || key.kty === "oct") malformed("Unregistered asymmetric JWK type");
	const result: Record<string, unknown> = {};
	for (const name of [...JWK_METADATA_MEMBERS, ...definition.publicMembers]) {
		if (!Object.hasOwn(key, name)) continue;
		const value = key[name];
		if (value === undefined) continue;
		if (typeof value !== "string" && (!["key_ops", "x5c"].includes(name) || !Array.isArray(value)))
			malformed(`Invalid JWK ${name}`);
		result[name] = Array.isArray(value) ? Array.from(value) : value;
	}
	metadata(result as Jwk);
	return result as PublicJwk;
}

/** Check public material against its registered JWK format, independently of signing usage. */
export function assertPublicJwk(key: Jwk, registry = DEFAULT_JWS_REGISTRY): PublicJwk {
	if (
		!key ||
		typeof key !== "object" ||
		PRIVATE_JWK_MEMBERS.some((name) => Object.hasOwn(key, name))
	)
		malformed("Expected a JWK without private parameters");
	const publicKey = toPublicJwk(key, registry);
	const definition = registry.keyType(publicKey.kty);
	if (!definition) malformed("Unregistered asymmetric JWK type");
	for (const value of Object.values(publicKey)) if (Array.isArray(value)) Object.freeze(value);
	Object.freeze(publicKey);
	try {
		definition.validatePublicKey(publicKey);
	} catch (cause) {
		if (cause instanceof CryptoError) throw cause;
		malformed("Invalid public key material", cause);
	}
	return publicKey;
}

/** Check that public material and key usage agree with a registered signing algorithm. */
export function assertVerificationKey(
	key: Jwk,
	algorithm: string,
	registry = DEFAULT_JWS_REGISTRY,
): PublicJwk {
	const definition = isAsymmetricIdentifier(algorithm) ? registry.algorithm(algorithm) : undefined;
	if (!definition)
		throw new CryptoError("UNSUPPORTED_ALGORITHM", `Unsupported algorithm: ${String(algorithm)}`);
	const publicKey = assertPublicJwk(key, registry);
	if (publicKey.kty !== definition.keyType) malformed("JWK type does not match algorithm");
	if (publicKey.kid !== undefined && !publicKey.kid) malformed("Invalid JWK kid");
	if (publicKey.alg !== undefined && publicKey.alg !== algorithm)
		malformed("JWK algorithm mismatch");
	if (publicKey.use !== undefined && publicKey.use !== "sig")
		malformed("JWK use does not permit signatures");
	if (publicKey.key_ops !== undefined && !publicKey.key_ops.includes("verify"))
		malformed("JWK key_ops must permit verification");
	try {
		definition.validatePublicKey(publicKey);
	} catch (cause) {
		malformed("JWK cannot be used with the selected algorithm", cause);
	}
	return key;
}

/** Capture a public signing identity with a nonempty kid and a registered algorithm. */
export function assertSigningPublicJwk(
	key: Jwk,
	registry = DEFAULT_JWS_REGISTRY,
): SigningPublicJwk {
	if (!key || typeof key.kid !== "string" || !key.kid || !key.alg)
		malformed("Signing identities require kid and alg");
	return toPublicJwk(assertVerificationKey(key, key.alg, registry), registry) as SigningPublicJwk;
}

/** Compare canonical public material, independently of kid, algorithm and usage. */
export function samePublicKey(left: Jwk, right: Jwk, registry = DEFAULT_JWS_REGISTRY): boolean {
	if (left.kty !== right.kty) return false;
	const definition = registry.keyType(left.kty);
	return (
		definition?.thumbprintMembers.every(
			(member) => typeof left[member] === "string" && left[member] === right[member],
		) === true
	);
}

function formatFor(
	key: Jwk,
	algorithm: string,
	registry: JwsAlgorithmRegistry,
): JwsSignatureFormat {
	const definition = isAsymmetricIdentifier(algorithm) ? registry.algorithm(algorithm) : undefined;
	if (!definition)
		throw new CryptoError("UNSUPPORTED_ALGORITHM", `Unsupported algorithm: ${algorithm}`);
	const format = definition.signature;
	if (!("byteLength" in format)) return format;
	const byteLength =
		typeof format.byteLength === "function" ? format.byteLength(key) : format.byteLength;
	if (!Number.isSafeInteger(byteLength) || byteLength <= 0)
		throw new CryptoError(
			"ENGINE_CONTRACT_VIOLATION",
			"Signature length must be a positive safe integer",
		);
	return { byteLength };
}

/** Return the exact width for a registered fixed-width signature. */
export function signatureByteLength(
	key: Jwk,
	algorithm: string,
	registry = DEFAULT_JWS_REGISTRY,
): number {
	const publicKey = assertVerificationKey(key, algorithm, registry);
	const format = formatFor(publicKey, algorithm, registry);
	if (!("byteLength" in format))
		throw new CryptoError("UNSUPPORTED_ALGORITHM", "Signature is variable-width");
	return format.byteLength as number;
}

/** Capture signature bounds and format checks for a previously validated public key. */
export function jwsSignatureRules(
	key: PublicJwk,
	algorithm: string,
	registry = DEFAULT_JWS_REGISTRY,
) {
	const format = formatFor(key, algorithm, registry);
	if ("byteLength" in format) {
		const length = format.byteLength as number;
		return {
			minimumBytes: length,
			accepts: (signature: Uint8Array) => signature.length === length,
		};
	}
	return {
		minimumBytes: format.minBytes,
		accepts: (signature: Uint8Array) =>
			signature.length >= format.minBytes &&
			signature.length <= format.maxBytes &&
			format.validate(signature.slice(), key) === true,
	};
}

/** Hash the registered RFC 7638 public members using the engine's SHA-256 operation. */
export async function jwkThumbprint(
	engine: CryptoEngine,
	key: Jwk,
	registry = DEFAULT_JWS_REGISTRY,
): Promise<Uint8Array> {
	const publicKey = assertPublicJwk(toPublicJwk(key, registry), registry);
	if (
		publicKey.kty === "EC" &&
		!["P-256", "P-384", "P-521"].includes(publicKey.crv ?? "") &&
		(!publicKey.alg || isJwsAlgorithm(publicKey.alg) || !registry.algorithm(publicKey.alg))
	)
		malformed("A custom EC curve requires a registered algorithm for thumbprinting");
	const definition = registry.keyType(publicKey.kty);
	if (!definition) malformed("Unsupported thumbprint key type");
	const members: Record<string, string> = {};
	for (const field of ["kty", ...definition.thumbprintMembers].sort()) {
		const value = publicKey[field];
		if (typeof value !== "string" || !value) malformed(`Missing thumbprint member ${field}`);
		members[field] = value;
	}
	const digest = await engine.digest("SHA-256", utf8Encode(JSON.stringify(members)));
	if (!(digest instanceof Uint8Array) || digest.length !== 32)
		throw new CryptoError("ENGINE_CONTRACT_VIOLATION", "SHA-256 must return 32 bytes");
	return digest.slice();
}
