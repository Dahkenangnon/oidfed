import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	entityId,
	type JWK,
	JWKSchema,
	type JwtSigner,
	nowSeconds,
	ok,
	type ReplayStore,
	type Result,
	type TrustAnchorSet,
} from "@oidfed/core";
import { z } from "zod";
import { decodeToken, signToken, verifyToken } from "./jwt.js";
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
	cnf: z.looseObject({ jwk: JWKSchema }),
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
export interface AuthenticateWalletOptions extends WalletTrustOptions {
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
): Promise<Result<true>> {
	if (typeof policy !== "function" || options.signal?.aborted)
		return failure("Required verification policy is missing or cancelled");
	try {
		const accepted = await runOperation(
			(signal) => policy(structuredClone(context), signal),
			options,
		);
		return accepted === true ? ok(true) : failure("Verification policy rejected the input");
	} catch {
		return failure("Verification policy failed, timed out, or was cancelled");
	}
}

export async function createAttestation(
	issuer: string,
	params: CreateWalletAttestationParams,
	signer: JwtSigner,
	options: WalletTrustOptions,
): Promise<Result<string>> {
	const parsed = AttestationSchema.safeParse({
		...params.claims,
		iss: issuer,
		sub: params.subject,
		exp: params.expiresAt,
		cnf: { jwk: params.confirmationKey },
	});
	if (!parsed.success || parsed.data.exp <= nowSeconds(options.clock))
		return failure("Invalid Wallet Attestation claims or expiration");
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
	options: WalletTrustOptions,
): Promise<Result<VerifiedWalletAttestation>> {
	const decoded = decodeToken(jwt, options);
	if (!decoded.ok) return decoded;
	const input = AttestationSchema.safeParse(decoded.value.payload);
	if (!input.success) return failure("Invalid Wallet Attestation claims");
	const headerChain = decoded.value.header.trust_chain;
	if (
		headerChain !== undefined &&
		(!Array.isArray(headerChain) || !headerChain.every((item) => typeof item === "string"))
	)
		return failure("Invalid trust_chain header");
	const provider = await trustedEntity("openid_wallet_provider", input.data.iss, anchors, {
		...options,
		...(headerChain ? { trustChain: headerChain as string[] } : {}),
	});
	if (!provider.ok) return provider;
	const keys = await protocolKeys(provider.value, "openid_wallet_provider", options);
	if (!keys.ok) return keys;
	const checked = await verifyToken(jwt, keys.value, "oauth-client-attestation+jwt", options);
	if (!checked.ok) return checked;
	return ok({ attestation: input.data, provider: provider.value });
}

export async function authenticateWallet(
	attestationJwt: string,
	popJwt: string,
	anchors: TrustAnchorSet,
	options: AuthenticateWalletOptions,
): Promise<Result<VerifiedWalletAttestation>> {
	const maxAge = options.maxProofAgeSeconds ?? 300;
	const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	try {
		entityId(options.audience);
	} catch {
		return failure("Expected authorization server audience must be a valid issuer identifier");
	}
	if (
		!Number.isFinite(maxAge) ||
		maxAge <= 0 ||
		!Number.isFinite(skew) ||
		skew < 0 ||
		!options.replayStore ||
		typeof options.acceptWallet !== "function" ||
		!options.audience
	)
		return failure("Invalid wallet authentication configuration");
	const verified = await verifyAttestation(attestationJwt, anchors, options);
	if (!verified.ok) return verified;
	const parsed = decodeToken(popJwt, options);
	if (!parsed.ok) return parsed;
	const proof = PopSchema.safeParse(parsed.value.payload);
	if (!proof.success) return failure("Invalid attestation proof claims");
	const claims = proof.data;
	const attestation = verified.value.attestation;
	if (
		claims.iss !== attestation.sub ||
		(options.clientId !== undefined && options.clientId !== claims.iss)
	)
		return failure("Wallet client identifiers do not match");
	if (options.expectedChallenge !== undefined && claims.challenge !== options.expectedChallenge)
		return failure("Wallet challenge does not match");
	const expiresAt = Math.min(claims.iat + maxAge, claims.exp ?? Infinity, attestation.exp) + skew;
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
	);
	if (!checked.ok) return checked;
	const accepted = await invokePolicy(options.acceptWallet, verified.value, options);
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
	);
	if (!replay.ok)
		return failure(
			"Attestation proof was already used or replay protection could not be completed",
		);
	if (!fresh() || options.signal?.aborted)
		return failure("Wallet authentication expired or was cancelled");
	return verified;
}
