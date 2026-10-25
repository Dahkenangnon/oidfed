import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_MAX_RESPONSE_BYTES,
	isValidAlgorithm,
	JWKSchema,
	type JWKSet,
	type JwtSigner,
	nowSeconds,
	ok,
	type Result,
	selectVerificationKey,
} from "@oidfed/core";
import * as jose from "jose";
import { runOperation } from "./operation.js";
import { failure, type WalletTrustOptions } from "./trust.js";

export function decodeToken(
	jwt: string,
	options: WalletTrustOptions,
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

export async function verifyToken(
	jwt: string,
	keys: JWKSet,
	typ: string,
	options: WalletTrustOptions,
	audience?: string,
): Promise<Result<jose.JWTPayload>> {
	const decoded = decodeToken(jwt, options);
	if (!decoded.ok) return decoded;
	const { header } = decoded.value;
	for (const claim of ["iat", "nbf", "exp"]) {
		const value = decoded.value.payload[claim];
		if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value)))
			return failure("JWT dates must be finite NumericDates");
	}
	if (header.typ !== typ || !isValidAlgorithm(header.alg))
		return failure("Invalid JWT type or unsupported signing algorithm");
	if (options.signal?.aborted) return failure("Operation cancelled");
	for (const key of keys.keys) {
		if (!JWKSchema.safeParse(key).success || (key.key_ops && !key.key_ops.includes("verify")))
			continue;
		if (header.kid !== undefined && header.kid !== key.kid) continue;
		if (
			!selectVerificationKey(
				{ alg: header.alg, ...(key.kid ? { kid: key.kid } : {}) },
				{ keys: [key] },
			)
		)
			continue;
		try {
			const imported = await jose.importJWK(key as jose.JWK, header.alg);
			const checked = await jose.jwtVerify(jwt, imported, {
				algorithms: [header.alg],
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

export async function signToken(
	payload: Record<string, unknown>,
	typ: string,
	signer: JwtSigner,
	options: WalletTrustOptions,
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
