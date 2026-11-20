/** Immutable, application-scoped definitions for asymmetric compact JWS. */
import { decodeBase64url } from "./encoding.js";
import { CryptoError, JWS_ALGORITHMS, type PublicJwk } from "./types.js";

/** Signature representation required by an algorithm's compact JWS profile. */
export type JwsSignatureFormat =
	| { readonly byteLength: number | ((key: PublicJwk) => number) }
	| {
			readonly minBytes: number;
			readonly maxBytes: number;
			readonly validate: (signature: Uint8Array, key: PublicJwk) => boolean;
	  };

/** Describe public material and JWS signature bytes. The engine performs signature verification. */
export interface JwsAlgorithmDefinition {
	readonly id: string;
	readonly keyType: string;
	/** Throw for a public key that cannot be used with this algorithm. */
	readonly validatePublicKey: (key: PublicJwk) => void;
	readonly signature: JwsSignatureFormat;
}

/** Describe a public asymmetric JWK format. List only fields safe to publish. */
export interface JwkTypeDefinition {
	readonly keyType: string;
	readonly publicMembers: readonly string[];
	/** Required public string members for RFC 7638. The registry adds kty. */
	readonly thumbprintMembers: readonly string[];
	/** Throw for invalid material. The key is a detached projection of public fields. */
	readonly validatePublicKey: (key: PublicJwk) => void;
}

/** Extensions installed by the application, alongside the built-in definitions. */
export interface JwsRegistryExtensions {
	readonly algorithms?: readonly JwsAlgorithmDefinition[];
	readonly keyTypes?: readonly JwkTypeDefinition[];
}

/** Public lookups into an immutable set of JWS and JWK definitions. */
export interface JwsAlgorithmRegistry {
	algorithm(id: string): JwsAlgorithmDefinition | undefined;
	keyType(id: string): JwkTypeDefinition | undefined;
}

export const PRIVATE_JWK_MEMBERS = Object.freeze(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);
export const JWK_METADATA_MEMBERS = Object.freeze([
	"kty",
	"kid",
	"alg",
	"use",
	"key_ops",
	"x5u",
	"x5c",
	"x5t",
	"x5t#S256",
]);
const PROHIBITED_ALGORITHMS = new Set(["none", "HS256", "HS384", "HS512"]);
const CURVES: ReadonlyMap<string, number> = new Map([
	["P-256", 32],
	["P-384", 48],
	["P-521", 66],
]);

function parameter(key: PublicJwk, name: string, length?: number): Uint8Array {
	const value = key[name];
	if (typeof value !== "string" || !value)
		throw new CryptoError("MALFORMED_KEY", `JWK ${name} must be a nonempty string`);
	try {
		const bytes = decodeBase64url(value);
		if (length === undefined || bytes.length === length) return bytes;
	} catch (cause) {
		throw new CryptoError("MALFORMED_KEY", `Invalid JWK ${name} encoding`, { cause });
	}
	throw new CryptoError("MALFORMED_KEY", `Invalid JWK ${name} length`);
}

function rsaLength(key: PublicJwk): number {
	const modulus = parameter(key, "n");
	const exponent = parameter(key, "e");
	if (modulus[0] === 0 || exponent[0] === 0)
		throw new CryptoError("MALFORMED_KEY", "RSA integers must use minimal unsigned encoding");
	const bits = (modulus.length - 1) * 8 + 32 - Math.clz32(modulus[0] ?? 0);
	if (bits < 2048) throw new CryptoError("MALFORMED_KEY", "RSA keys require at least 2048 bits");
	if (
		(exponent[exponent.length - 1] ?? 0) % 2 === 0 ||
		(exponent.length === 1 && (exponent[0] ?? 0) < 3)
	)
		throw new CryptoError("MALFORMED_KEY", "Invalid RSA public exponent");
	return modulus.length;
}

function curveKey(key: PublicJwk, curve: string): void {
	if (key.crv !== curve) throw new CryptoError("MALFORMED_KEY", `Signature requires ${curve}`);
	if (curve === "Ed25519") {
		parameter(key, "x", 32);
	} else {
		parameter(key, "x", CURVES.get(curve));
		parameter(key, "y", CURVES.get(curve));
	}
}

const keyTypes: readonly JwkTypeDefinition[] = [
	{
		keyType: "RSA",
		publicMembers: ["n", "e"],
		thumbprintMembers: ["e", "n"],
		validatePublicKey: rsaLength,
	},
	{
		keyType: "EC",
		publicMembers: ["crv", "x", "y"],
		thumbprintMembers: ["crv", "x", "y"],
		validatePublicKey(key) {
			if (!key.crv) throw new CryptoError("MALFORMED_KEY", "Missing EC curve");
			curveKey(key, key.crv);
		},
	},
	{
		keyType: "OKP",
		publicMembers: ["crv", "x"],
		thumbprintMembers: ["crv", "x"],
		validatePublicKey(key) {
			if (!key.crv) throw new CryptoError("MALFORMED_KEY", "Missing OKP curve");
			const widths = new Map([
				["Ed25519", 32],
				["Ed448", 57],
				["X25519", 32],
				["X448", 56],
			]);
			parameter(key, "x", widths.get(key.crv));
		},
	},
];

const builtinCurves = {
	ES256: ["P-256", 64],
	ES384: ["P-384", 96],
	ES512: ["P-521", 132],
	Ed25519: ["Ed25519", 64],
	EdDSA: ["Ed25519", 64],
} as const;
const algorithms: readonly JwsAlgorithmDefinition[] = JWS_ALGORITHMS.map((id) => {
	if (id in builtinCurves) {
		const [curve, byteLength] = builtinCurves[id as keyof typeof builtinCurves];
		return {
			id,
			keyType: curve === "Ed25519" ? "OKP" : "EC",
			validatePublicKey: (key) => curveKey(key, curve),
			signature: { byteLength },
		};
	}
	return { id, keyType: "RSA", validatePublicKey: rsaLength, signature: { byteLength: rsaLength } };
});

function identifier(value: unknown): value is string {
	return (
		typeof value === "string" &&
		/^[\x21-\x7e]+$/.test(value) &&
		(!value.includes(":") || /^[a-z][a-z0-9+.-]*:.+/i.test(value))
	);
}

/** Check the identifier boundary before consulting application definitions. */
export function isAsymmetricIdentifier(value: unknown): value is string {
	return identifier(value) && !PROHIBITED_ALGORITHMS.has(value);
}

function positiveLength(value: unknown): value is number {
	return Number.isSafeInteger(value) && (value as number) > 0;
}

/** Install host definitions without mutating the built-ins or other applications' registries. */
export function createJwsAlgorithmRegistry(
	extensions: JwsRegistryExtensions = {},
): JwsAlgorithmRegistry {
	const keyDefinitions = new Map<string, JwkTypeDefinition>();
	for (const definition of [...keyTypes, ...(extensions.keyTypes ?? [])]) {
		const { keyType, validatePublicKey } = definition;
		const publicMembers = Object.freeze([...definition.publicMembers]);
		const thumbprintMembers = Object.freeze([...definition.thumbprintMembers]);
		if (
			!identifier(keyType) ||
			keyType === "oct" ||
			keyDefinitions.has(keyType) ||
			typeof validatePublicKey !== "function" ||
			!publicMembers.length ||
			new Set(publicMembers).size !== publicMembers.length ||
			publicMembers.some(
				(name) =>
					!identifier(name) ||
					[
						...PRIVATE_JWK_MEMBERS,
						...JWK_METADATA_MEMBERS,
						"__proto__",
						"constructor",
						"prototype",
					].includes(name),
			) ||
			!thumbprintMembers.length ||
			new Set(thumbprintMembers).size !== thumbprintMembers.length ||
			thumbprintMembers.some((name) => !publicMembers.includes(name))
		) {
			throw new TypeError("Invalid or duplicate asymmetric JWK type definition");
		}
		keyDefinitions.set(
			keyType,
			Object.freeze({ keyType, publicMembers, thumbprintMembers, validatePublicKey }),
		);
	}
	const algorithmDefinitions = new Map<string, JwsAlgorithmDefinition>();
	for (const definition of [...algorithms, ...(extensions.algorithms ?? [])]) {
		const { id, keyType, validatePublicKey } = definition;
		const signature = Object.freeze({ ...definition.signature });
		if (
			!isAsymmetricIdentifier(id) ||
			algorithmDefinitions.has(id) ||
			!keyDefinitions.has(keyType) ||
			typeof validatePublicKey !== "function"
		)
			throw new TypeError("Invalid or duplicate asymmetric JWS algorithm definition");
		const validSignature =
			"byteLength" in signature
				? typeof signature.byteLength === "function" || positiveLength(signature.byteLength)
				: positiveLength(signature.minBytes) &&
					positiveLength(signature.maxBytes) &&
					signature.minBytes <= signature.maxBytes &&
					typeof signature.validate === "function";
		if (!validSignature) throw new TypeError("Invalid JWS signature format");
		algorithmDefinitions.set(id, Object.freeze({ id, keyType, validatePublicKey, signature }));
	}
	return Object.freeze({
		algorithm: (id: string) => algorithmDefinitions.get(id),
		keyType: (id: string) => keyDefinitions.get(id),
	});
}

/** Built-in definitions, shared by operations without an application registry. */
export const DEFAULT_JWS_REGISTRY = createJwsAlgorithmRegistry();
