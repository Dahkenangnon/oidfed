/** Shared signing and verification primitives for protocol JWTs beyond Entity Statements. */

// biome-ignore assist/source/organizeImports: Preserve dependency evaluation order.
import { runAsyncOperation as runOperation } from "../async-operation.js";
import {
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
	DEFAULT_ALLOWED_ALGORITHMS,
} from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { FederationOptions } from "../types.js";
import { isValidAlgorithm } from "./keys.js";
import type { KeyringEntry } from "@oidfed/crypto";
import { DEFAULT_MAX_COMPACT_JWS_BYTES, decodeCompactJws, utf8Encode } from "@oidfed/crypto";
import { JwsService } from "../jws-service.js";

const failure = (description: string): Result<never> =>
	err({ code: FederationErrorCode.InvalidRequest, description });

/** Decode a size-bounded JWT without authenticating its header or claims. */
export function decodeApplicationJwt(
	jwt: string,
	options: Pick<FederationOptions, "maxResponseBytes" | "maxCompactBytes">,
): Result<{ header: Record<string, unknown>; payload: Record<string, unknown> }> {
	if (
		typeof jwt !== "string" ||
		jwt.length > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
	)
		return failure("JWT exceeds the configured size limit");
	try {
		return ok(
			decodeCompactJws(jwt, {
				maxBytes: options.maxCompactBytes ?? DEFAULT_MAX_COMPACT_JWS_BYTES,
			}),
		);
	} catch {
		return failure("Malformed JWT");
	}
}

/** RFC 7515 §4.1.9 treats typ as a media type, with an optional application/ prefix. */
export function matchesJwtType(actual: unknown, expected: string): boolean {
	if (typeof actual !== "string") return false;
	const mediaType = (value: string) => {
		const lower = value.toLowerCase();
		return lower.includes("/") ? lower : `application/${lower}`;
	};
	return mediaType(actual) === mediaType(expected);
}

/** ACA §9 allows applications to narrow the backend's supported algorithms. */
export function checkApplicationJwtHeader(
	header: Record<string, unknown>,
	typ: string,
	allowed?: readonly string[],
	registry?: import("@oidfed/crypto").JwsAlgorithmRegistry,
): Result<string> {
	if (
		allowed !== undefined &&
		(!Array.isArray(allowed) ||
			!allowed.length ||
			!allowed.every((alg) => isValidAlgorithm(alg, registry)))
	)
		return failure("Invalid allowed signing algorithms");
	if (
		!matchesJwtType(header.typ, typ) ||
		!isValidAlgorithm(header.alg, registry) ||
		!(allowed ?? (DEFAULT_ALLOWED_ALGORITHMS as readonly string[])).includes(header.alg)
	)
		return failure("Invalid JWT type or unsupported signing algorithm");
	return ok(header.alg as string);
}

/**
 * Verify a protocol JWT's header, signature, times, and supplied audience expectation.
 * The caller establishes trust in the verification keys and applies protocol-specific claim rules.
 */
export async function verifyApplicationJwt(
	jwt: string,
	keys: JWKSet,
	typ: string,
	options: FederationOptions,
	audience?: string,
	confirmationKey = false,
	allowedAlgorithms?: readonly string[],
): Promise<Result<Record<string, unknown>>> {
	if (
		typeof jwt !== "string" ||
		jwt.length > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
	)
		return failure("JWT exceeds the configured size limit");
	const result = await new JwsService(options).verifyJwt(
		jwt,
		keys,
		{
			typ: { expected: typ, comparison: "media-type" },
			keyId: confirmationKey ? "confirmation-key" : "allow-missing",
			...(audience === undefined
				? {}
				: { audience: { expected: audience, mode: "contains" as const } }),
		},
		allowedAlgorithms === undefined ? {} : { allowedAlgorithms },
	);
	if (!result.ok)
		return ["ERR_CRYPTO_OPERATION_FAILED", "ERR_INVALID_CLOCK"].includes(result.error.code)
			? result
			: failure(result.error.description);
	return ok(result.value.payload);
}

/** Serialize and sign a protocol payload with the requested JWT type and optional trust chain. */
export async function signApplicationJwt(
	payload: Record<string, unknown>,
	typ: string,
	signer: KeyringEntry,
	options: FederationOptions,
	chain?: readonly string[],
): Promise<Result<string>> {
	if (options.signal?.aborted) return failure("Operation cancelled");
	try {
		if (
			utf8Encode(JSON.stringify(payload)).length >
			(options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
		)
			return failure("JWT payload exceeds the size limit");
		const token = await runOperation(
			() =>
				new JwsService(options).signJwt(signer, payload, {
					typ,
					...(chain ? { trust_chain: chain } : {}),
				}),
			options,
		);
		if (token.length > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES))
			return failure("JWT exceeds the configured size limit");
		return options.signal?.aborted ? failure("Operation cancelled") : ok(token);
	} catch {
		return failure("Protocol JWT signing failed");
	}
}
