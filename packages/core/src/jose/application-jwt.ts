import { runAsyncOperation as runOperation } from "../async-operation.js";
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
	SUPPORTED_ALGORITHMS,
} from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import { JWKSchema, type JWKSet } from "../schemas/jwk.js";
import { type FederationOptions, nowSeconds } from "../types.js";
import { isValidAlgorithm, selectVerificationKey } from "./keys.js";
import type { JwtSigner } from "./signer.js";

const failure = (description: string): Result<never> =>
	err({ code: FederationErrorCode.InvalidRequest, description });

import * as jose from "jose";

export function decodeApplicationJwt(
	jwt: string,
	options: FederationOptions,
): Result<{ header: jose.ProtectedHeaderParameters; payload: jose.JWTPayload }> {
	if (
		typeof jwt !== "string" ||
		jwt.length > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
	)
		return failure("JWT exceeds the configured size limit");
	try {
		return ok({ header: jose.decodeProtectedHeader(jwt), payload: jose.decodeJwt(jwt) });
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
	header: jose.ProtectedHeaderParameters,
	typ: string,
	allowed?: readonly string[],
): Result<string> {
	if (
		allowed !== undefined &&
		(!Array.isArray(allowed) || !allowed.length || !allowed.every(isValidAlgorithm))
	)
		return failure("Invalid allowed signing algorithms");
	if (
		!matchesJwtType(header.typ, typ) ||
		!isValidAlgorithm(header.alg) ||
		!(allowed ?? (SUPPORTED_ALGORITHMS as readonly string[])).includes(header.alg)
	)
		return failure("Invalid JWT type or unsupported signing algorithm");
	return ok(header.alg as string);
}

export async function verifyApplicationJwt(
	jwt: string,
	keys: JWKSet,
	typ: string,
	options: FederationOptions,
	audience?: string,
	confirmationKey = false,
	allowedAlgorithms?: readonly string[],
): Promise<Result<jose.JWTPayload>> {
	const decoded = decodeApplicationJwt(jwt, options);
	if (!decoded.ok) return decoded;
	const { header } = decoded.value;
	for (const claim of ["iat", "nbf", "exp"]) {
		const value = decoded.value.payload[claim];
		if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value)))
			return failure("JWT dates must be finite NumericDates");
	}
	const headerCheck = checkApplicationJwtHeader(header, typ, allowedAlgorithms);
	if (!headerCheck.ok) return headerCheck;
	const alg = headerCheck.value;
	if (options.signal?.aborted) return failure("Operation cancelled");
	for (const key of keys.keys) {
		if (!JWKSchema.safeParse(key).success || (key.key_ops && !key.key_ops.includes("verify")))
			continue;
		// ACA §5.2 designates cnf.jwk itself; an absent key identifier is not a mismatch.
		// A supplied hint still needs the string syntax defined by RFC 7515 §4.1.4.
		if (
			header.kid !== undefined &&
			header.kid !== key.kid &&
			!(
				confirmationKey &&
				typeof header.kid === "string" &&
				keys.keys.length === 1 &&
				key.kid === undefined
			)
		)
			continue;
		if (!selectVerificationKey({ alg, ...(key.kid ? { kid: key.kid } : {}) }, { keys: [key] }))
			continue;
		try {
			const imported = await jose.importJWK(key as jose.JWK, alg);
			const checked = await jose.jwtVerify(jwt, imported, {
				algorithms: [alg],
				typ,
				currentDate: new Date(nowSeconds(options.clock) * 1000),
				clockTolerance: options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS,
				...(audience !== undefined ? { audience } : {}),
			});
			if (options.signal?.aborted) return failure("Operation cancelled");
			return ok(checked.payload);
		} catch {
			/* Try other eligible public keys when the format permits omission of kid. */
		}
	}
	return failure("JWT signature or claims could not be verified with the trusted protocol keys");
}

export async function signApplicationJwt(
	payload: Record<string, unknown>,
	typ: string,
	signer: JwtSigner,
	options: FederationOptions,
	chain?: readonly string[],
): Promise<Result<string>> {
	if (!isValidAlgorithm(signer.alg) || !signer.kid || options.signal?.aborted)
		return failure("Invalid signer or cancelled operation");
	try {
		const bytes = new TextEncoder().encode(JSON.stringify(payload));
		if (bytes.length > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES))
			return failure("JWT payload exceeds the size limit");
		const token = await runOperation(
			() =>
				signer.signJwt(bytes, {
					alg: signer.alg,
					kid: signer.kid,
					typ,
					...(chain ? { trust_chain: chain } : {}),
				}),
			options,
		);
		if (options.signal?.aborted) return failure("Operation cancelled");
		if (token.length > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES))
			return failure("Signed JWT exceeds the configured size limit");
		return ok(token);
	} catch {
		return failure("Protocol JWT signing failed");
	}
}
