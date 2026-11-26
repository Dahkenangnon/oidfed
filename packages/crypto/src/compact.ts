/** Compact JSON JWS parsing and signing. Claim and trust validation belong to the caller. */
import { decodeBase64url, encodeBase64url, utf8Decode, utf8Encode } from "./encoding.js";
import { assertSigningPublicJwk, jwsSignatureRules } from "./jwk.js";
import {
	DEFAULT_JWS_REGISTRY,
	isAsymmetricIdentifier,
	type JwsAlgorithmRegistry,
} from "./registry.js";
import { CryptoError, type JwsAlgorithm, type Signer } from "./types.js";

/** Default maximum UTF-8 byte length of a compact token: 512 KiB. */
export const DEFAULT_MAX_COMPACT_JWS_BYTES = 512 * 1024;

/** A compact JWS exceeded its configured byte limit. */
export class CompactJwsSizeError extends CryptoError {
	/** Preserve the existing category for consumers that handle malformed compact tokens. */
	constructor() {
		super("MALFORMED_JWS", "Compact JWS exceeds maxBytes");
		this.name = "CompactJwsSizeError";
	}
}
/** Size bound shared by signing, decoding and strict parsing. */
export interface CompactJwsOptions {
	/** Positive safe integer; defaults to DEFAULT_MAX_COMPACT_JWS_BYTES. */
	readonly maxBytes?: number | undefined;
	/** Application algorithm definitions for signing and strict parsing. */
	readonly algorithmRegistry?: JwsAlgorithmRegistry | undefined;
}
/** Header accepted by the signing helper and strict parser; not evidence of verification. */
export interface ProtectedHeader {
	/** Supported asymmetric signing algorithm. */
	readonly alg: JwsAlgorithm;
	/** Optional when parsing; signing requires the selected signer's identifier. */
	readonly kid?: string;
	/** Token type. Protocol code decides whether a particular value or absence is required. */
	readonly typ?: string;
	readonly [parameter: string]: unknown;
}
/** Header and claims decoded for inspection only. No signature or token policy is checked. */
export interface DecodedCompactJws {
	readonly header: Record<string, unknown>;
	readonly payload: Record<string, unknown>;
	/** Original serialization, retained without re-encoding. */
	readonly compact: string;
}
/** Parsed data is unverified, including its header and payload. */
export interface ParsedCompactJws {
	readonly header: ProtectedHeader;
	readonly payload: Record<string, unknown>;
	/** Exact ASCII bytes of the original encoded header, dot and encoded payload. */
	readonly signingInput: Uint8Array;
	/** Decoded JWS signature bytes. */
	readonly signature: Uint8Array;
	/** Original token for inspection; verification engines consume the bytes above. */
	readonly compact: string;
}

function limit(options?: CompactJwsOptions): number {
	const value = options?.maxBytes ?? DEFAULT_MAX_COMPACT_JWS_BYTES;
	if (!Number.isSafeInteger(value) || value <= 0)
		throw new CryptoError("MALFORMED_JWS", "maxBytes must be a positive safe integer");
	return value;
}
function checkSize(size: number, maximum: number): void {
	if (size > maximum) throw new CompactJwsSizeError();
}
function object(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}
function decodeObject(segment: string): Record<string, unknown> {
	try {
		const value: unknown = JSON.parse(utf8Decode(decodeBase64url(segment)));
		if (!object(value)) throw new TypeError("Expected a JSON object");
		return value;
	} catch (cause) {
		throw new CryptoError("MALFORMED_JWS", "Expected base64url-encoded UTF-8 JSON object", {
			cause,
		});
	}
}

function segments(compact: string, options?: CompactJwsOptions): [string, string, string] {
	if (typeof compact !== "string")
		throw new CryptoError("MALFORMED_JWS", "Expected a compact JWS string");
	const maximum = limit(options);
	// Bound allocation before encoding an opaque signature segment that may contain Unicode.
	checkSize(compact.length, maximum);
	checkSize(utf8Encode(compact).length, maximum);
	const parts = compact.split(".");
	if (parts.length !== 3)
		throw new CryptoError("MALFORMED_JWS", "Compact JWS requires three segments");
	return parts as [string, string, string];
}

/** Decode encoded JSON header and payload objects without checking token policy.
 * Unknown algorithms, critical headers and opaque or empty signature segments are
 * left uninterpreted. The payload must still be base64url-encoded JSON.
 * @throws {CryptoError} MALFORMED_JWS for invalid structure, encoding, JSON or size options.
 */
export function decodeCompactJws(compact: string, options?: CompactJwsOptions): DecodedCompactJws {
	const [protectedHeader, payload] = segments(compact, options);
	return { header: decodeObject(protectedHeader), payload: decodeObject(payload), compact };
}

/** Check supported algorithms, header shapes and the encoded-payload critical-header rules.
 * @throws {CryptoError} UNSUPPORTED_ALGORITHM for an unknown algorithm; MALFORMED_JWS for header violations.
 */
export function assertSupportedHeader(
	header: Record<string, unknown>,
	registry = DEFAULT_JWS_REGISTRY,
): asserts header is Record<string, unknown> & ProtectedHeader {
	if (!isAsymmetricIdentifier(header.alg) || !registry.algorithm(header.alg))
		throw new CryptoError("UNSUPPORTED_ALGORITHM", "Unsupported JWS algorithm");
	if (header.kid !== undefined && (typeof header.kid !== "string" || !header.kid))
		throw new CryptoError("MALFORMED_JWS", "Invalid kid");
	if (header.typ !== undefined && typeof header.typ !== "string")
		throw new CryptoError("MALFORMED_JWS", "Invalid typ");
	const crit = header.crit;
	if (crit !== undefined) {
		if (
			!Array.isArray(crit) ||
			!crit.length ||
			new Set(crit).size !== crit.length ||
			crit.some(
				(name: unknown) =>
					typeof name !== "string" || name !== "b64" || !Object.hasOwn(header, name),
			)
		) {
			throw new CryptoError("MALFORMED_JWS", "Unsupported or malformed critical headers");
		}
	}
	if (
		Object.hasOwn(header, "b64") &&
		(header.b64 !== true || !Array.isArray(crit) || !crit.includes("b64"))
	) {
		throw new CryptoError("MALFORMED_JWS", "JWT b64 must be true and listed in crit");
	}
}

/** Parse a supported compact JSON JWS, including its exact verification bytes.
 * Checks syntax and supported headers, but not the signature, claims or key provenance.
 * @throws {CryptoError} MALFORMED_JWS for invalid input; UNSUPPORTED_ALGORITHM for an unknown algorithm.
 */
export function parseCompactJws(compact: string, options?: CompactJwsOptions): ParsedCompactJws {
	const parts = segments(compact, options);
	const header = decodeObject(parts[0]);
	assertSupportedHeader(header, options?.algorithmRegistry);
	const payload = decodeObject(parts[1] ?? "");
	const signature = decodeBase64url(parts[2] ?? "");
	if (!signature.length) throw new CryptoError("MALFORMED_JWS", "Signature must not be empty");
	return {
		header,
		payload,
		signature,
		compact,
		signingInput: utf8Encode(`${parts[0]}.${parts[1]}`),
	};
}

/** Serialize once and sign those exact segments with the selected signing binding.
 * Read one keyring entry before building payloads that advertise its JWKS. This
 * helper checks the header against the signer, not the payload's claims or keys.
 * @throws {CryptoError} MALFORMED_KEY, MALFORMED_JWS or SIGNER_CONTRACT_VIOLATION for invalid inputs or output.
 * Errors from the host's signing callback propagate unchanged.
 */
export async function signCompactJws(
	payload: Record<string, unknown>,
	header: ProtectedHeader,
	signer: Signer,
	options?: CompactJwsOptions,
): Promise<string> {
	const maximum = limit(options);
	const registry = options?.algorithmRegistry;
	const identity = assertSigningPublicJwk(signer.publicJwk, registry);
	let encodedHeader: string;
	let encodedPayload: string;
	try {
		encodedHeader = encodeBase64url(utf8Encode(JSON.stringify(header)));
		encodedPayload = encodeBase64url(utf8Encode(JSON.stringify(payload)));
	} catch (cause) {
		throw new CryptoError("MALFORMED_JWS", "Payload and header must be JSON serializable", {
			cause,
		});
	}
	checkSize(encodedHeader.length + encodedPayload.length + 2, maximum);
	const capturedHeader = decodeObject(encodedHeader);
	assertSupportedHeader(capturedHeader, registry);
	decodeObject(encodedPayload);
	if (capturedHeader.alg !== identity.alg || capturedHeader.kid !== identity.kid) {
		throw new CryptoError("SIGNER_CONTRACT_VIOLATION", "Header does not match selected signer");
	}
	const rules = jwsSignatureRules(identity, identity.alg, registry);
	checkSize(
		encodedHeader.length + encodedPayload.length + 2 + Math.ceil((rules.minimumBytes * 4) / 3),
		maximum,
	);
	const input = `${encodedHeader}.${encodedPayload}`;
	const signature = await signer.sign(utf8Encode(input));
	if (!(signature instanceof Uint8Array) || !rules.accepts(signature)) {
		throw new CryptoError(
			"SIGNER_CONTRACT_VIOLATION",
			"Signer returned an invalid JWS signature size or type",
		);
	}
	const result = `${input}.${encodeBase64url(signature)}`;
	checkSize(result.length, maximum);
	return result;
}
