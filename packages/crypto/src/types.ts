/** Supported asymmetric JWS identifiers. EdDSA is the legacy Ed25519 identifier here. */
export type BuiltinJwsAlgorithm =
	| "ES256"
	| "ES384"
	| "ES512"
	| "PS256"
	| "PS384"
	| "PS512"
	| "RS256"
	| "Ed25519"
	| "EdDSA";

/** Wire algorithm identifier. Resolve it through a configured registry before use. */
export type JwsAlgorithm = string;

/** Built-in algorithm identifiers. */
export const JWS_ALGORITHMS: readonly BuiltinJwsAlgorithm[] = Object.freeze([
	"ES256",
	"ES384",
	"ES512",
	"PS256",
	"PS384",
	"PS512",
	"RS256",
	"Ed25519",
	"EdDSA",
]);
/** Default adapter capability list. Edwards algorithms require explicit opt-in. */
export const CLASSICAL_ALGORITHMS: readonly BuiltinJwsAlgorithm[] = Object.freeze(
	JWS_ALGORITHMS.filter((algorithm) => algorithm !== "Ed25519" && algorithm !== "EdDSA"),
);
/** Federation §3 recommends RS256 verification; deployments choose their own policy. */
export const INTEROP_RECOMMENDED_ALGORITHMS: readonly BuiltinJwsAlgorithm[] = Object.freeze([
	"RS256",
]);
/** Hash algorithms used by federation helpers and host signing integrations. */
export type DigestAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";

/** A wire JWK; runtime validation determines whether its material is usable. */
export interface Jwk {
	/** Key type, such as EC, RSA or OKP. */
	readonly kty: string;
	/** Identifier; protocols decide when it is required. */
	readonly kid?: string | undefined;
	/** Optional algorithm restriction carried by the key. */
	readonly alg?: string | undefined;
	/** Intended use; signing helpers accept sig when present. */
	readonly use?: string | undefined;
	/** Permitted operations. Verification requires verify when this member is present. */
	readonly key_ops?: readonly string[] | undefined;
	/** Named curve for EC and OKP keys. */
	readonly crv?: string | undefined;
	/** Base64url-encoded public coordinates or Edwards public key. */
	readonly x?: string | undefined;
	/** Base64url-encoded second EC coordinate. */
	readonly y?: string | undefined;
	/** Minimal unsigned base64url RSA modulus. */
	readonly n?: string | undefined;
	/** Minimal unsigned base64url RSA public exponent. */
	readonly e?: string | undefined;
	readonly [parameter: string]: unknown;
}

/** A public asymmetric JWK. Protocols decide whether an identifier is required. */
export interface PublicJwk extends Jwk {}
/** Public identity of one signing binding; private parameters are forbidden. */
export interface SigningPublicJwk extends PublicJwk {
	/** Nonempty identifier that remains bound to the same key. */
	readonly kid: string;
	/** Algorithm permanently associated with this signing operation. */
	readonly alg: JwsAlgorithm;
}
/** Wire-format public key collection. Consumers must validate its contents and provenance. */
export interface JwkSet {
	readonly keys: readonly Jwk[];
}

/** Original JWS bytes and the public key selected by the caller. */
export interface JwsVerifyInput {
	/** Algorithm from the protected header, after the caller applies its token policy. */
	readonly algorithm: JwsAlgorithm;
	/** Caller-selected, authenticated public key. It may have no kid. */
	readonly key: PublicJwk;
	/** Exact ASCII bytes of encoded protected header, dot and encoded payload. Never reserialize JSON. */
	readonly signingInput: Uint8Array;
	/** Authoritative signature bytes; fixed-width R || S for ECDSA. */
	readonly signature: Uint8Array;
}

/** Invalid signatures return false; unsupported operations and backend failures reject. */
export interface CryptoEngine {
	/** Configured capability ceiling; callers still choose their accepted algorithms. */
	readonly algorithms: readonly JwsAlgorithm[];
	/** Check that public material can be used by this backend for the requested algorithm.
	 * Resolve without a value; malformed keys, unsupported operations and backend failures reject.
	 * This does not establish ownership, trust, or possession of the private key.
	 */
	validatePublicKey(key: PublicJwk, algorithm: JwsAlgorithm): Promise<void>;
	/** Check only the supplied signature. Return a literal boolean; do not validate claims or resolve keys. */
	verify(input: JwsVerifyInput): Promise<boolean>;
	/** Return fresh digest bytes: 32, 48 or 64 bytes for the respective SHA algorithm. */
	digest(algorithm: DigestAlgorithm, data: Uint8Array): Promise<Uint8Array>;
	/** Return exactly byteLength bytes from a cryptographically secure generator. */
	random(byteLength: number): Promise<Uint8Array>;
}

/** Bind one immutable key identity and algorithm to a private-key operation. */
export interface Signer {
	/** Detached public metadata for the immutable key binding; never include private material. */
	readonly publicJwk: SigningPublicJwk;
	/** Sign raw JWS input; return JWS signature bytes (fixed-width R||S for ECDSA). */
	sign(signingInput: Uint8Array): Promise<Uint8Array>;
}

/** Application-defined signing purpose. The named values are suggestions, not required entries. */
export type KeyPurpose =
	| "federation"
	| "request_object"
	| "client_assertion"
	| "wallet_attestation"
	| `trust_mark:${string}`
	| (string & Record<never, never>);

/** Framework-neutral facts a custom keyring may use when selecting a signer. */
export interface KeySelectionContext {
	/** Issuer for the operation, if known. */
	readonly issuer?: string;
	/** Subject for the operation, if known. */
	readonly subject?: string;
	/** Trust-mark type used by a host's selection policy. */
	readonly trustMarkType?: string;
	/** Host-defined selection facts; default keyrings do not interpret them. */
	readonly extensions?: Readonly<Record<string, string>>;
}

/** Detached, frozen metadata and a stable signing binding, read together. */
export interface KeyringEntry {
	/** Binding selected in the same read as the published keys. */
	readonly signer: Signer;
	/** Use this exact snapshot when the payload advertises its own keys. */
	readonly publishedJwks: JwkSet;
}
/** Select signing bindings without exposing how the host stores private keys. */
export interface Keyring {
	/** Return an immutable snapshot, or reject if the purpose has no available signer. */
	entry(purpose: KeyPurpose, context?: KeySelectionContext): Promise<KeyringEntry>;
}

/** Recorded Unix seconds; active and overlap keys have no invented end time. */
export interface HistoricalKeyRecord {
	/** Detached public identity; endpoint-specific lifetime fields are added by protocol code. */
	readonly publicJwk: SigningPublicJwk;
	/** Recorded introduction into this keyring, not key creation or confirmed network publication. */
	readonly publishedAt?: number;
	/** First activation for signing, in Unix seconds. */
	readonly activatedAt?: number;
	/** Withdrawal after publication or overlap, in Unix seconds. */
	readonly retiredAt?: number;
	/** Revocation time, in Unix seconds. Can coexist with an earlier retirement. */
	readonly revokedAt?: number;
	/** Host-supplied reason recorded on first revocation. */
	readonly revocationReason?: string;
}
/** Publication lifecycle. Hosts own propagation delays, durable storage and retirement scheduling. */
export interface RotatingKeyring extends Keyring {
	/** Make a new key eligible for publication without selecting it for signing. */
	publish(purpose: KeyPurpose, signer: Signer): Promise<void>;
	/** Select a published key and retain the former active key during overlap. */
	activate(purpose: KeyPurpose, kid: string): Promise<void>;
	/** Withdraw a published or overlap key; repeating retirement preserves its first timestamp. */
	retire(purpose: KeyPurpose, kid: string): Promise<void>;
	/** Withdraw a managed key. Previously returned snapshots remain bound to their original signers. */
	revoke(purpose: KeyPurpose, kid: string, reason: string): Promise<void>;
	/** Return recorded facts for activated or withdrawn keys; these are not historical-endpoint wire objects. */
	history(purpose: KeyPurpose): Promise<readonly HistoricalKeyRecord[]>;
}

/** Stable failure categories. A signature mismatch is false, not an error code. */
export type CryptoErrorCode =
	| "UNSUPPORTED_ALGORITHM"
	| "UNSUPPORTED_RUNTIME"
	| "MALFORMED_KEY"
	| "MALFORMED_JWS"
	| "KEY_NOT_FOUND"
	| "SIGNER_CONTRACT_VIOLATION"
	| "ENGINE_CONTRACT_VIOLATION"
	| "CRYPTO_OPERATION_FAILED";

/** Typed failure shared by adapters and helpers within each module format. */
export class CryptoError extends Error {
	/** Machine-readable category; use it when translating failures into protocol results. */
	readonly code: CryptoErrorCode;
	/** Construct a failure, retaining an optional backend cause without logging it. */
	constructor(code: CryptoErrorCode, message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "CryptoError";
		this.code = code;
	}
}
/** Unsupported cryptographic operation or configured algorithm capability. */
export class CryptoUnsupportedError extends CryptoError {
	/** Construct an UNSUPPORTED_ALGORITHM failure with an optional cause. */
	constructor(message: string, options?: ErrorOptions) {
		super("UNSUPPORTED_ALGORITHM", message, options);
		this.name = "CryptoUnsupportedError";
	}
}

/** Test whether a value is one of this package's supported asymmetric identifiers. */
export function isJwsAlgorithm(value: unknown): value is BuiltinJwsAlgorithm {
	return typeof value === "string" && (JWS_ALGORITHMS as readonly string[]).includes(value);
}
