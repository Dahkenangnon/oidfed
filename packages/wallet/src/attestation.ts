import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_MAX_RESPONSE_BYTES,
	entityId,
	type JWK,
	JWKSchema,
	type JwtSigner,
	nowSeconds,
	ok,
	preparePublicJwkSet,
	type ReplayStore,
	type Result,
	SUPPORTED_ALGORITHMS,
	safeLogger,
	type TrustAnchorSet,
} from "@oidfed/core";
import * as jose from "jose";
import { z } from "zod";
import { checkProtocolHeader, decodeToken, signToken, verifyToken } from "./jwt.js";
import { runOperation } from "./operation.js";
import {
	failure,
	protocolKeys,
	type TrustedWalletEntity,
	trustedEntity,
	type WalletTrustOptions,
} from "./trust.js";

const nonempty = z.string().min(1);
export const AttestationSchema = z.looseObject({
	iss: nonempty,
	sub: nonempty,
	exp: z.number(),
	cnf: z
		.looseObject({ jwk: JWKSchema })
		.refine(
			(cnf) => !Object.hasOwn(cnf, "jwe") && !Object.hasOwn(cnf, "jku"),
			"RFC 7800 permits only one key representation",
		),
	iat: z.number().optional(),
	nbf: z.number().optional(),
	wallet_name: z.string().optional(),
	wallet_link: z.url().optional(),
});
const PopSchema = z.looseObject({
	iss: nonempty,
	aud: z.union([nonempty, z.array(nonempty).min(1)]),
	jti: nonempty,
	iat: z.number(),
	nbf: z.number().optional(),
	exp: z.number().optional(),
	challenge: z.string().optional(),
});
export type WalletAttestation = z.infer<typeof AttestationSchema>;
export interface VerifiedWalletAttestation {
	readonly attestation: WalletAttestation;
	readonly provider: TrustedWalletEntity;
}
export interface CreateWalletAttestationParams {
	readonly subject: string;
	readonly confirmationKey: JWK;
	readonly expiresAt: number;
	readonly claims?: Readonly<Record<string, unknown>>;
}
/** Receiver binding for an attestation that supplies aud (RFC 7519 §4.1.3). */
export interface WalletAttestationVerificationOptions extends WalletTrustOptions {
	readonly expectedAudience?: string;
	readonly allowedAttestationAlgorithms?: readonly string[];
}
export interface AuthenticateWalletOptions
	extends Omit<WalletAttestationVerificationOptions, "expectedAudience"> {
	readonly allowedProofAlgorithms?: readonly string[];
	readonly audience: string;
	readonly clientId?: string;
	readonly expectedChallenge?: string;
	readonly maxProofAgeSeconds?: number;
	readonly replayStore: ReplayStore;
	readonly acceptWallet: (
		verified: VerifiedWalletAttestation,
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}

/** Bound application verification hooks and release the caller promptly on cancellation. */
export async function invokePolicy<T>(
	policy: (context: T, signal?: AbortSignal) => boolean | Promise<boolean>,
	context: T,
	options: WalletTrustOptions,
	operation = "Application verification",
): Promise<Result<true>> {
	const logger = safeLogger(options.logger);
	if (options.signal?.aborted) {
		logger?.debug(`${operation} cancelled`);
		return failure("Required verification policy is missing or cancelled");
	}
	if (typeof policy !== "function") {
		logger?.warn(`${operation} callback is required`);
		return failure("Required verification policy is missing or cancelled");
	}
	try {
		const accepted = await runOperation(
			(signal) => policy(structuredClone(context), signal),
			options,
		);
		if (accepted === true) return ok(true);
		logger?.warn(`${operation} rejected the input`);
		return failure("Verification policy rejected the input");
	} catch {
		if (options.signal?.aborted) logger?.debug(`${operation} cancelled`);
		else logger?.error(`${operation} failed or timed out`);
		return failure("Verification policy failed, timed out, or was cancelled");
	}
}

export async function createAttestation(
	issuer: string,
	params: CreateWalletAttestationParams,
	signer: JwtSigner,
	options: WalletTrustOptions,
): Promise<Result<string>> {
	safeLogger(options?.logger)?.debug("Creating a Wallet Attestation");

	const parsed = AttestationSchema.safeParse({
		...params.claims,
		iss: issuer,
		sub: params.subject,
		exp: params.expiresAt,
		cnf: { jwk: params.confirmationKey },
	});
	const now = nowSeconds(options.clock);
	// ACA §5.1 allows historical issuance and delayed activation; these intervals
	// must still be usable. Callers own the accuracy of an explicit historical iat.
	if (
		!parsed.success ||
		parsed.data.exp <= now ||
		(parsed.data.iat !== undefined && parsed.data.iat > now) ||
		(parsed.data.nbf !== undefined && parsed.data.nbf >= parsed.data.exp)
	)
		return failure("Invalid Wallet Attestation claims or expiration");
	const key = await validateConfirmationKey(parsed.data.cnf.jwk);
	if (!key.ok) return key;
	return signToken(
		parsed.data,
		"oauth-client-attestation+jwt",
		signer,
		options,
		options.trustChain,
	);
}

export async function verifyAttestation(
	jwt: string,
	anchors: TrustAnchorSet,
	options: WalletAttestationVerificationOptions,
): Promise<Result<VerifiedWalletAttestation>> {
	safeLogger(options?.logger)?.debug("Verifying a Wallet Attestation");

	const decoded = decodeToken(jwt, options);
	if (!decoded.ok) return decoded;
	const header = checkProtocolHeader(
		decoded.value.header,
		"oauth-client-attestation+jwt",
		options.allowedAttestationAlgorithms,
	);
	if (!header.ok) return header;
	const input = AttestationSchema.safeParse(decoded.value.payload);
	if (!input.success) return failure("Invalid Wallet Attestation claims");
	const confirmation = await validateConfirmationKey(input.data.cnf.jwk);
	if (!confirmation.ok) return confirmation;
	const now = nowSeconds(options.clock);
	const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	if (
		!Number.isFinite(skew) ||
		skew < 0 ||
		input.data.exp + skew <= now ||
		(input.data.nbf !== undefined && input.data.nbf > now + skew)
	)
		return failure("Wallet Attestation is outside its validity interval");
	const audience = decoded.value.payload.aud;
	if (
		audience !== undefined &&
		(!options.expectedAudience ||
			!(typeof audience === "string"
				? audience === options.expectedAudience
				: Array.isArray(audience) &&
					audience.every((item) => typeof item === "string") &&
					audience.includes(options.expectedAudience)))
	) {
		safeLogger(options?.logger)?.warn(
			"Wallet Attestation aud requires a matching expectedAudience",
		);
		return failure("Wallet Attestation audience requires a matching expectedAudience");
	}
	const headerChain = decoded.value.header.trust_chain;
	if (
		headerChain !== undefined &&
		(!Array.isArray(headerChain) || !headerChain.every((item) => typeof item === "string"))
	)
		return failure("Invalid trust_chain header");
	const provider = await trustedEntity(
		"openid_wallet_provider",
		input.data.iss,
		anchors,
		options,
		headerChain as readonly string[] | undefined,
	);
	if (!provider.ok) return provider;
	const keys = await protocolKeys(provider.value, "openid_wallet_provider", options);
	if (!keys.ok) return keys;
	const checked = await verifyToken(
		jwt,
		keys.value,
		"oauth-client-attestation+jwt",
		options,
		audience === undefined ? undefined : options.expectedAudience,
		false,
		options.allowedAttestationAlgorithms,
	);
	if (!checked.ok) return checked;
	safeLogger(options?.logger)?.info("Wallet Attestation verification completed");
	return ok({ attestation: input.data, provider: provider.value });
}

export async function authenticateWallet(
	attestationJwt: string,
	popJwt: string,
	anchors: TrustAnchorSet,
	options: AuthenticateWalletOptions,
): Promise<Result<VerifiedWalletAttestation>> {
	safeLogger(options?.logger)?.debug("Authenticating a Wallet with Client Attestation PoP");

	const maxAge = options.maxProofAgeSeconds ?? 300;
	const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	try {
		entityId(options.audience);
	} catch {
		safeLogger(options?.logger)?.warn(
			"Client Attestation PoP requires a valid authorization server audience",
		);
		return failure("Expected authorization server audience must be a valid issuer identifier");
	}
	if (!options.replayStore)
		safeLogger(options.logger)?.warn(
			"Provide a replayStore for Client Attestation PoP replay protection",
		);
	if (typeof options.acceptWallet !== "function")
		safeLogger(options.logger)?.warn("Provide acceptWallet to decide whether to accept the Wallet");
	if (
		!Number.isFinite(maxAge) ||
		maxAge <= 0 ||
		!Number.isFinite(skew) ||
		skew < 0 ||
		!options.replayStore ||
		typeof options.acceptWallet !== "function" ||
		!options.audience ||
		(options.expectedChallenge !== undefined &&
			(typeof options.expectedChallenge !== "string" ||
				options.expectedChallenge.trim().length === 0))
	)
		return failure("Invalid wallet authentication configuration");

	const parsed = decodeToken(popJwt, options);
	if (!parsed.ok) return parsed;
	const header = checkProtocolHeader(
		parsed.value.header,
		"oauth-client-attestation-pop+jwt",
		options.allowedProofAlgorithms,
	);
	if (!header.ok) return header;
	const proof = PopSchema.safeParse(parsed.value.payload);
	if (!proof.success) return failure("Invalid attestation proof claims");
	const claims = proof.data;
	// These unverified fields may reject a request early; acceptance still requires both signatures.
	const decodedAttestation = decodeToken(attestationJwt, options);
	if (!decodedAttestation.ok) return decodedAttestation;
	const attestationInput = AttestationSchema.safeParse(decodedAttestation.value.payload);
	if (!attestationInput.success) return failure("Invalid Wallet Attestation claims");
	const attestation = attestationInput.data;
	if (
		claims.iss !== attestation.sub ||
		(options.clientId !== undefined && options.clientId !== claims.iss)
	)
		return failure("Wallet client identifiers do not match");
	if (options.expectedChallenge !== undefined && claims.challenge !== options.expectedChallenge)
		return failure("Wallet challenge does not match");
	const expiresAt = Math.min(claims.iat + maxAge, claims.exp ?? Infinity, attestation.exp) + skew;
	const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
	if (
		!audiences.includes(options.audience) ||
		claims.iat > nowSeconds(options.clock) + skew ||
		expiresAt <= nowSeconds(options.clock) ||
		(claims.nbf !== undefined && claims.nbf > nowSeconds(options.clock) + skew)
	)
		return failure("Attestation proof audience or freshness check failed");
	const verified = await verifyAttestation(attestationJwt, anchors, {
		...options,
		expectedAudience: options.audience,
	});
	if (!verified.ok) return verified;
	const fresh = () =>
		claims.iat <= nowSeconds(options.clock) + skew &&
		expiresAt > nowSeconds(options.clock) &&
		verified.value.provider.trustChain.expiresAt > nowSeconds(options.clock);
	if (!fresh()) return failure("Attestation proof is outside the allowed freshness window");
	const checked = await verifyToken(
		popJwt,
		{ keys: [attestation.cnf.jwk] },
		"oauth-client-attestation-pop+jwt",
		options,
		options.audience,
		true,
		options.allowedProofAlgorithms,
	);
	if (!checked.ok) return checked;
	const accepted = await invokePolicy(
		options.acceptWallet,
		verified.value,
		options,
		"Wallet acceptance",
	);
	if (!accepted.ok) return accepted;
	if (!fresh() || options.signal?.aborted)
		return failure("Wallet authentication expired or was cancelled");
	const replay = await invokePolicy(
		() =>
			options.replayStore.useJti({
				issuer: claims.iss,
				audience: options.audience,
				jti: claims.jti,
				expiresAt,
			}),
		undefined,
		options,
		"Client Attestation PoP replay protection",
	);
	if (!replay.ok)
		return failure(
			"Attestation proof was already used or replay protection could not be completed",
		);
	if (!fresh() || options.signal?.aborted)
		return failure("Wallet authentication expired or was cancelled");
	return verified;
}

/** Validate the designated PoP key, without tightening received federation JWK Sets. */
async function validateConfirmationKey(key: JWK): Promise<Result<true>> {
	// The set helper checks public material. This local identifier does not alter cnf.jwk.
	const material = preparePublicJwkSet({ keys: [{ ...key, kid: key.kid ?? "confirmation" }] });
	if (!material.ok) return failure("Invalid Wallet Attestation confirmation key material");
	if (
		(key.use !== undefined && key.use !== "sig") ||
		(key.key_ops !== undefined && !key.key_ops.includes("verify"))
	)
		return failure("Wallet Attestation confirmation key must permit signature verification");
	for (const alg of SUPPORTED_ALGORITHMS) {
		if (key.alg !== undefined && key.alg !== alg) continue;
		const curves: Readonly<Record<string, string>> = {
			ES256: "P-256",
			ES384: "P-384",
			ES512: "P-521",
		};
		const curve = curves[alg];
		if (curve ? key.kty !== "EC" || key.crv !== curve : key.kty !== "RSA") continue;
		try {
			const imported = await jose.importJWK(key as jose.JWK, alg);
			if (imported instanceof Uint8Array) continue;
			if ("modulusLength" in imported.algorithm && Number(imported.algorithm.modulusLength) < 2048)
				continue;
			return ok(true);
		} catch {
			/* Try another compatible supported algorithm. */
		}
	}
	return failure("Wallet Attestation confirmation key has no usable signing algorithm");
}

/** ACA §7.2 syntax parsing; authenticate the returned pair before accepting its claims. */
export function parseConcatenatedWalletAttestation(
	value: string,
	options: Pick<WalletTrustOptions, "maxResponseBytes"> = {},
): Result<{ attestationJwt: string; popJwt: string }> {
	const limit = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
	if (
		!Number.isSafeInteger(limit) ||
		limit <= 0 ||
		typeof value !== "string" ||
		value.length > limit
	)
		return failure("Invalid or oversized concatenated attestation");
	const parts = value.split("~");
	if (parts.length !== 2) return failure("Concatenated attestation requires exactly two JWTs");
	const [attestationJwt, popJwt] = parts;
	if (!attestationJwt || !popJwt)
		return failure("Concatenated attestation requires two nonempty JWTs");
	for (const jwt of parts) {
		if (
			!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jwt) ||
			// RFC 7515 Appendix C: a base64url length modulo four of one is malformed.
			jwt.split(".").some((segment) => segment.length % 4 === 1) ||
			!decodeToken(jwt, options).ok
		)
			return failure("Concatenated attestation contains a malformed JWT");
	}
	return ok({ attestationJwt, popJwt });
}
