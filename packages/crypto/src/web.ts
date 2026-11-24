/** Optional Web Crypto backend. Global crypto is resolved at construction, never import. */
import {
	assertSigningPublicJwk,
	assertVerificationKey,
	type BuiltinJwsAlgorithm,
	CLASSICAL_ALGORITHMS,
	type CryptoEngine,
	CryptoError,
	CryptoUnsupportedError,
	type DigestAlgorithm,
	decodeBase64url,
	isJwsAlgorithm,
	type Jwk,
	jwsSignatureRules,
	type Signer,
	type SigningPublicJwk,
	toPublicJwk,
} from "@oidfed/crypto";
import { assertEcPublicPoint } from "./ec-public-key.js";

/** Structural Web Crypto types keep DOM and Node declaration packages out of the contract. */
export interface WebCryptoAlgorithm {
	/** Web Crypto operation name; this is not a JOSE algorithm identifier. */
	readonly name: string;
	/** EC curve used when importing keys. */
	readonly namedCurve?: string;
	/** Hash selected for RSA import or ECDSA operations. */
	readonly hash?: DigestAlgorithm;
	/** RSA-PSS salt length in bytes. */
	readonly saltLength?: number;
}
/** Structural backend interface. Key handles stay inside the injected implementation.
 * It must follow Web Crypto's byte formats and output contracts, including raw R || S for ECDSA.
 */
export interface WebCryptoLike<Key = unknown> {
	/** Native or compatible cryptographic operations; no key-export operation is required. */
	readonly subtle: {
		/** Import a detached JWK for the requested operation. */
		importKey(
			format: "jwk",
			key: object,
			algorithm: WebCryptoAlgorithm,
			extractable: boolean,
			usages: ("sign" | "verify")[],
		): Promise<Key>;
		/** Resolve to a literal boolean; reject backend failures. */
		verify(
			algorithm: WebCryptoAlgorithm,
			key: Key,
			signature: ArrayBuffer,
			data: ArrayBuffer,
		): Promise<boolean>;
		/** Return signature bytes in Web Crypto's format. */
		sign(algorithm: WebCryptoAlgorithm, key: Key, data: ArrayBuffer): Promise<ArrayBuffer>;
		/** Return the requested hash bytes. */
		digest(algorithm: DigestAlgorithm, data: ArrayBuffer): Promise<ArrayBuffer>;
	};
	/** Fill the supplied view with secure randomness and return that same view. */
	getRandomValues(array: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;
}
/** Adapter capability configuration. This does not establish token acceptance policy. */
export interface WebCryptoEngineOptions {
	/** Distinct supported identifiers; defaults to CLASSICAL_ALGORITHMS. Runtime support is checked on use. */
	readonly algorithms?: readonly BuiltinJwsAlgorithm[];
}

const SPECS: Record<
	BuiltinJwsAlgorithm,
	{
		import: WebCryptoAlgorithm;
		operation: WebCryptoAlgorithm;
	}
> = {
	ES256: {
		import: { name: "ECDSA", namedCurve: "P-256" },
		operation: { name: "ECDSA", hash: "SHA-256" },
	},
	ES384: {
		import: { name: "ECDSA", namedCurve: "P-384" },
		operation: { name: "ECDSA", hash: "SHA-384" },
	},
	ES512: {
		import: { name: "ECDSA", namedCurve: "P-521" },
		operation: { name: "ECDSA", hash: "SHA-512" },
	},
	PS256: {
		import: { name: "RSA-PSS", hash: "SHA-256" },
		operation: { name: "RSA-PSS", saltLength: 32 },
	},
	PS384: {
		import: { name: "RSA-PSS", hash: "SHA-384" },
		operation: { name: "RSA-PSS", saltLength: 48 },
	},
	PS512: {
		import: { name: "RSA-PSS", hash: "SHA-512" },
		operation: { name: "RSA-PSS", saltLength: 64 },
	},
	RS256: {
		import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		operation: { name: "RSASSA-PKCS1-v1_5" },
	},
	RS384: {
		import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
		operation: { name: "RSASSA-PKCS1-v1_5" },
	},
	RS512: {
		import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
		operation: { name: "RSASSA-PKCS1-v1_5" },
	},
	Ed25519: { import: { name: "Ed25519" }, operation: { name: "Ed25519" } },
	EdDSA: { import: { name: "Ed25519" }, operation: { name: "Ed25519" } },
};

function resolveWeb<Key>(implementation?: WebCryptoLike<Key>): WebCryptoLike<Key> {
	const value = implementation ?? (globalThis as unknown as { crypto?: WebCryptoLike<Key> }).crypto;
	if (
		!value?.subtle ||
		typeof value.getRandomValues !== "function" ||
		["importKey", "sign", "verify", "digest"].some(
			(name) => typeof value.subtle[name as keyof WebCryptoLike["subtle"]] !== "function",
		)
	) {
		throw new CryptoError(
			"UNSUPPORTED_RUNTIME",
			"Supply a Web Crypto implementation with importKey, sign, verify, digest and getRandomValues",
		);
	}
	return value;
}
function bytes(input: Uint8Array): ArrayBuffer {
	if (!(input instanceof Uint8Array))
		throw new CryptoError("MALFORMED_JWS", "Expected Uint8Array bytes");
	return new Uint8Array(input).buffer;
}
function importable(key: Jwk): object {
	const fields: Record<string, unknown> = { ...key };
	// Agreement is validated before import. Explicit Web Crypto parameters also work
	// in runtimes whose JWK alg vocabulary predates fully specified JOSE identifiers.
	delete fields.alg;
	if (key.key_ops) fields.key_ops = [...key.key_ops];
	return fields;
}

// JWKs are JSON dictionaries. Copy only fields the asymmetric importer understands,
// rather than requiring a general object-cloning API or retaining host-owned objects.
function copyPrivateJwk(key: Jwk): Jwk {
	const copy: Record<string, unknown> = { ...toPublicJwk(key) };
	for (const name of ["d", "p", "q", "dp", "dq", "qi"]) {
		const value = key[name];
		if (value === undefined) continue;
		if (typeof value !== "string")
			throw new CryptoError("MALFORMED_KEY", `Invalid private JWK ${name}`);
		copy[name] = value;
	}
	if (key.ext !== undefined) {
		if (typeof key.ext !== "boolean")
			throw new CryptoError("MALFORMED_KEY", "Invalid private JWK ext");
		copy.ext = key.ext;
	}
	if (key.oth !== undefined) {
		if (!Array.isArray(key.oth)) throw new CryptoError("MALFORMED_KEY", "Invalid private JWK oth");
		copy.oth = key.oth.map((value: unknown) => {
			if (value === null || typeof value !== "object" || Array.isArray(value))
				throw new CryptoError("MALFORMED_KEY", "Invalid private JWK other-prime record");
			const record = value as Record<string, unknown>;
			if (
				typeof record.r !== "string" ||
				typeof record.d !== "string" ||
				typeof record.t !== "string"
			)
				throw new CryptoError("MALFORMED_KEY", "Invalid private JWK other-prime parameters");
			return { r: record.r, d: record.d, t: record.t };
		});
	}
	return copy as Jwk;
}
function failure(cause: unknown): never {
	if (cause instanceof CryptoError) throw cause;
	if (cause instanceof Error && cause.name === "NotSupportedError")
		throw new CryptoUnsupportedError("The runtime does not support this cryptographic operation", {
			cause,
		});
	if (cause instanceof Error && (cause.name === "DataError" || cause.name === "SyntaxError"))
		throw new CryptoError("MALFORMED_KEY", "The backend rejected key material", { cause });
	throw new CryptoError("CRYPTO_OPERATION_FAILED", "Cryptographic operation failed", { cause });
}

/** Create a Web Crypto engine using an injected implementation or the host's global crypto.
 * Backend lookup happens here, never on import. Inputs are copied before native operations.
 * @throws {CryptoError} UNSUPPORTED_RUNTIME if no suitable implementation is available.
 * @throws {CryptoUnsupportedError} If the configured capability list is invalid.
 */
export function createWebCryptoEngine<Key = unknown>(
	implementation?: WebCryptoLike<Key>,
	options?: WebCryptoEngineOptions,
): CryptoEngine {
	const web = resolveWeb(implementation);
	const algorithms = Object.freeze([...(options?.algorithms ?? CLASSICAL_ALGORITHMS)]);
	if (!algorithms.every(isJwsAlgorithm) || new Set(algorithms).size !== algorithms.length)
		throw new CryptoUnsupportedError("Capabilities must contain distinct supported algorithms");
	return Object.freeze({
		algorithms,
		async validatePublicKey(key, algorithm) {
			if (!isJwsAlgorithm(algorithm) || !algorithms.includes(algorithm))
				throw new CryptoUnsupportedError(`Engine does not support ${algorithm}`);
			assertVerificationKey(key, algorithm);
			assertEcPublicPoint(key);
			try {
				await web.subtle.importKey(
					"jwk",
					importable(toPublicJwk(key)),
					SPECS[algorithm].import,
					false,
					["verify"],
				);
			} catch (cause) {
				return failure(cause);
			}
		},
		async verify({ algorithm, key, signingInput, signature }) {
			if (!isJwsAlgorithm(algorithm) || !algorithms.includes(algorithm))
				throw new CryptoUnsupportedError(`Engine does not support ${algorithm}`);
			assertVerificationKey(key, algorithm);
			if (signature instanceof Uint8Array && !jwsSignatureRules(key, algorithm).accepts(signature))
				return false;
			assertEcPublicPoint(key);
			const spec = SPECS[algorithm];
			try {
				const imported = await web.subtle.importKey(
					"jwk",
					importable(toPublicJwk(key)),
					spec.import,
					false,
					["verify"],
				);
				const valid = await web.subtle.verify(
					spec.operation,
					imported,
					bytes(signature),
					bytes(signingInput),
				);
				if (typeof valid !== "boolean")
					throw new CryptoError("ENGINE_CONTRACT_VIOLATION", "Verification must return a boolean");
				return valid;
			} catch (cause) {
				return failure(cause);
			}
		},
		async digest(algorithm: DigestAlgorithm, data: Uint8Array) {
			const lengths = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };
			if (!Object.hasOwn(lengths, algorithm))
				throw new CryptoUnsupportedError("Unsupported digest algorithm");
			try {
				const value = new Uint8Array(await web.subtle.digest(algorithm, bytes(data)));
				if (value.length !== lengths[algorithm])
					throw new CryptoError("ENGINE_CONTRACT_VIOLATION", "Digest has incorrect length");
				return value;
			} catch (cause) {
				return failure(cause);
			}
		},
		async random(byteLength: number) {
			if (!Number.isSafeInteger(byteLength) || byteLength < 0)
				throw new CryptoError(
					"ENGINE_CONTRACT_VIOLATION",
					"Random byte count must be a nonnegative safe integer",
				);
			try {
				const value = new Uint8Array(byteLength);
				for (let offset = 0; offset < byteLength; offset += 65536) {
					const view = value.subarray(offset, Math.min(offset + 65536, byteLength));
					const result = web.getRandomValues(view);
					if (result !== view)
						throw new CryptoError(
							"ENGINE_CONTRACT_VIOLATION",
							"getRandomValues must return its input view",
						);
				}
				return value;
			} catch (cause) {
				return failure(cause);
			}
		},
	} satisfies CryptoEngine);
}

/** JWK-backed custody for software keys. Native and remote custody implement Signer directly. */
export class SoftwareSigner<Key = unknown> implements Signer {
	/** Frozen public identity. Private key_ops containing sign are published as verify. */
	readonly publicJwk: SigningPublicJwk;
	#privateJwk: Jwk | undefined;
	readonly #web: WebCryptoLike<Key>;
	readonly #algorithm: BuiltinJwsAlgorithm;
	#imported: Promise<Key> | undefined;

	/** Capture a private JWK and backend. The native private-key import is deferred until signing.
	 * Supported fields are detached, including certificate and RSA other-prime arrays;
	 * unknown import metadata is omitted. No private-key export is performed.
	 * @throws {CryptoError} MALFORMED_KEY for invalid key data; UNSUPPORTED_RUNTIME for a missing backend.
	 */
	constructor(
		privateJwk: Jwk & { readonly kid: string; readonly alg: BuiltinJwsAlgorithm },
		implementation?: WebCryptoLike<Key>,
	) {
		this.#web = resolveWeb(implementation);
		if (typeof privateJwk.d !== "string" || !privateJwk.d)
			throw new CryptoError("MALFORMED_KEY", "Software signing requires private key material");
		try {
			decodeBase64url(privateJwk.d);
		} catch (cause) {
			throw new CryptoError("MALFORMED_KEY", "Invalid private key encoding", { cause });
		}
		if (
			privateJwk.key_ops !== undefined &&
			(!Array.isArray(privateJwk.key_ops) || !privateJwk.key_ops.includes("sign"))
		)
			throw new CryptoError("MALFORMED_KEY", "Private key does not permit signing");
		const published = {
			...toPublicJwk(privateJwk),
			...(privateJwk.key_ops ? { key_ops: Object.freeze(["verify"]) } : {}),
		};
		const identity = assertSigningPublicJwk(published);
		for (const value of Object.values(identity)) if (Array.isArray(value)) Object.freeze(value);
		this.publicJwk = Object.freeze(identity);
		Object.defineProperty(this, "publicJwk", { writable: false, configurable: false });
		this.#algorithm = privateJwk.alg;
		this.#privateJwk = copyPrivateJwk(privateJwk);
	}
	/** Sign raw JWS input. Concurrent calls share one import. A successful import releases the
	 * captured JWK and a failed import can be retried on the next call.
	 * @throws {CryptoError} Typed key, unsupported-operation or backend failures.
	 */
	async sign(signingInput: Uint8Array): Promise<Uint8Array> {
		const spec = SPECS[this.#algorithm];
		try {
			if (!this.#imported) {
				const jwk = this.#privateJwk;
				if (!jwk) throw new CryptoError("MALFORMED_KEY", "Missing private key");
				this.#imported = this.#web.subtle
					.importKey("jwk", importable(jwk), spec.import, false, ["sign"])
					.then(
						(key) => {
							this.#privateJwk = undefined;
							return key;
						},
						(cause: unknown) => {
							this.#imported = undefined;
							throw cause;
						},
					);
			}
			return new Uint8Array(
				await this.#web.subtle.sign(spec.operation, await this.#imported, bytes(signingInput)),
			);
		} catch (cause) {
			return failure(cause);
		}
	}
}
