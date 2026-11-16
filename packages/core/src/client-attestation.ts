/** Client Attestation and proof-of-possession creation, verification, and authentication. */

import * as jose from "jose";
import { z } from "zod";
import { runAsyncOperation as runOperation } from "./async-operation.js";
import { isJsonData } from "./callbacks.js";
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
	SUPPORTED_ALGORITHMS,
} from "./constants.js";
import { err, type FederationError, ok, type Result } from "./errors.js";
import {
	checkApplicationJwtHeader as checkProtocolHeader,
	decodeApplicationJwt as decodeToken,
	signApplicationJwt as signToken,
	verifyApplicationJwt as verifyToken,
} from "./jose/application-jwt.js";
import type { JwtSigner } from "./jose/signer.js";
import { decodeEntityConfiguration } from "./jose/verify.js";
import { preparePublicJwkSet } from "./jwks/public-material.js";
import { safeLogger } from "./logging.js";
import type { ReplayStore } from "./replay-store.js";
import { type JWK, JWKSchema, type JWKSet } from "./schemas/jwk.js";
import { entityId, type FederationOptions, nowSeconds } from "./types.js";

/** Stable failure reason for a host's draft-07 HTTP response policy. */
export interface ClientAttestationError extends FederationError {
	readonly attestationError?:
		| "use_attestation_challenge"
		| "use_fresh_attestation"
		| "invalid_client_attestation";
}
const failure = (
	description: string,
	attestationError?: ClientAttestationError["attestationError"],
): Result<never, ClientAttestationError> =>
	err({
		code: FederationErrorCode.InvalidRequest,
		description,
		...(attestationError ? { attestationError } : {}),
	});
const invalidCredential = (error: FederationError): Result<never, ClientAttestationError> =>
	err({ ...error, attestationError: "invalid_client_attestation" });
const nonempty = z.string().min(1);
const AttestationSchema = z.looseObject({
	iss: nonempty,
	sub: nonempty,
	exp: z.number().finite(),
	cnf: z
		.looseObject({ jwk: JWKSchema })
		.refine(
			(cnf) => !Object.hasOwn(cnf, "jwe") && !Object.hasOwn(cnf, "jku"),
			"RFC 7800 permits only one key representation",
		),
	iat: z.number().finite().optional(),
	nbf: z.number().finite().optional(),
	wallet_name: z.string().optional(),
	wallet_link: z.url().optional(),
});
const PopSchema = z.looseObject({
	iss: nonempty,
	aud: z.union([nonempty, z.array(nonempty).min(1)]),
	jti: nonempty,
	iat: z.number().finite(),
	nbf: z.number().finite().optional(),
	exp: z.number().finite().optional(),
	challenge: z.string().optional(),
});
export type ClientAttestation = z.infer<typeof AttestationSchema>;
export interface ClientAttestationOptions extends FederationOptions {
	readonly trustChain?: readonly string[];
}
export interface TrustedClientAttester {
	readonly jwks: JWKSet;
	/** Expiry of the attester's trust evidence, independently of the attestation lifetime. */
	readonly expiresAt?: number;
}
export interface VerifiedClientAttestation {
	readonly attestation: ClientAttestation;
	readonly attester: TrustedClientAttester;
	/** Current verification deadline, including trust and proof freshness where applicable. */
	readonly expiresAt: number;
}
export interface VerifiedAttestationChallenge {
	readonly issuedAt: number;
	readonly expiresAt: number;
}
export type ClientAttestationFreshness =
	| { readonly mode: "iat"; readonly maxAgeSeconds?: number }
	| {
			readonly mode: "challenge";
			readonly verify: (
				challenge: string,
				signal: AbortSignal,
			) => Result<VerifiedAttestationChallenge> | Promise<Result<VerifiedAttestationChallenge>>;
	  };
export type ClientAttestationReplay =
	| { readonly mode: "jti"; readonly store: ReplayStore }
	| {
			readonly mode: "challenge";
			readonly consume: (
				challenge: string,
				expiresAt: number,
				signal: AbortSignal,
			) => boolean | Promise<boolean>;
	  }
	| { readonly mode: "freshness-only" };
export interface CreateClientAttestationParams {
	readonly subject: string;
	readonly confirmationKey: JWK;
	readonly expiresAt: number;
	readonly claims?: Readonly<Record<string, unknown>>;
}
/** Receiver binding for an attestation that supplies aud (RFC 7519 §4.1.3). */
export interface ClientAttestationVerificationOptions extends ClientAttestationOptions {
	readonly expectedAudience?: string;
	readonly allowedAttestationAlgorithms?: readonly string[];
	/** The issuer and header are unverified lookup hints, never trust evidence. */
	readonly getAttester: (
		issuer: string,
		header: Readonly<jose.ProtectedHeaderParameters>,
		signal: AbortSignal,
	) => Result<TrustedClientAttester> | Promise<Result<TrustedClientAttester>>;
}
export interface AuthenticateClientAttestationOptions
	extends Omit<ClientAttestationVerificationOptions, "expectedAudience"> {
	readonly allowedProofAlgorithms?: readonly string[];
	readonly audience: string;
	readonly clientId?: string;
	readonly expectedChallenge?: string;
	readonly maxProofAgeSeconds?: number;
	readonly replayStore?: ReplayStore;
	readonly freshness?: ClientAttestationFreshness;
	readonly replay?: ClientAttestationReplay;
	readonly acceptClient: (
		verified: VerifiedClientAttestation,
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}

/** Bound application verification hooks and release the caller promptly on cancellation. */
export async function invokeVerificationPolicy<T>(
	policy: (context: T, signal?: AbortSignal) => boolean | Promise<boolean>,
	context: T,
	options: ClientAttestationOptions,
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
		return err({
			code: FederationErrorCode.ServerError,
			description: "Verification policy failed, timed out, or was cancelled",
		});
	}
}

async function createClientAttestationImpl(
	issuer: string,
	params: CreateClientAttestationParams,
	signer: JwtSigner,
	options: ClientAttestationOptions,
): Promise<Result<string>> {
	safeLogger(options?.logger)?.debug("Creating a Client Attestation");

	if (
		!isJsonData(params.claims ?? {}) ||
		Object.keys(params.claims ?? {}).some((name) => ["iss", "sub", "exp", "cnf"].includes(name))
	)
		return failure("Additional claims cannot replace attestation identity or key claims");
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
		!Number.isFinite(now) ||
		parsed.data.exp <= now ||
		(parsed.data.iat !== undefined && parsed.data.iat > now) ||
		(parsed.data.nbf !== undefined && parsed.data.nbf >= parsed.data.exp)
	)
		return failure("Invalid Client Attestation claims or expiration");
	if (options.trustChain !== undefined) {
		const first: unknown = Array.isArray(options.trustChain) ? options.trustChain[0] : undefined;
		if (typeof first !== "string")
			return failure("trust_chain must begin with the attester's Entity Configuration");
		const configuration = decodeEntityConfiguration(first);
		if (
			!configuration.ok ||
			configuration.value.payload.iss !== issuer ||
			configuration.value.payload.sub !== issuer
		)
			return failure("trust_chain must begin with the attester's Entity Configuration");
	}
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

async function verifyClientAttestationImpl(
	jwt: string,
	options: ClientAttestationVerificationOptions,
): Promise<Result<VerifiedClientAttestation, ClientAttestationError>> {
	safeLogger(options?.logger)?.debug("Verifying a Client Attestation");

	const decoded = decodeToken(jwt, options);
	if (!decoded.ok) return invalidCredential(decoded.error);
	const header = checkProtocolHeader(
		decoded.value.header,
		"oauth-client-attestation+jwt",
		options.allowedAttestationAlgorithms,
	);
	if (!header.ok) return invalidCredential(header.error);
	const input = AttestationSchema.safeParse(decoded.value.payload);
	if (!input.success)
		return failure("Invalid Client Attestation claims", "invalid_client_attestation");
	const confirmation = await validateConfirmationKey(input.data.cnf.jwk);
	if (!confirmation.ok) return invalidCredential(confirmation.error);
	const now = nowSeconds(options.clock);
	const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	if (
		!Number.isFinite(skew) ||
		!Number.isFinite(now) ||
		skew < 0 ||
		(input.data.nbf !== undefined && input.data.nbf > now + skew)
	)
		return failure("Client Attestation is outside its validity interval");
	if (input.data.exp + skew <= now)
		return failure("Client Attestation has expired", "use_fresh_attestation");
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
			"Client Attestation aud requires a matching expectedAudience",
		);
		return failure("Client Attestation audience requires a matching expectedAudience");
	}
	const headerChain = decoded.value.header.trust_chain;
	if (
		headerChain !== undefined &&
		(!Array.isArray(headerChain) || !headerChain.every((item) => typeof item === "string"))
	)
		return failure("Invalid trust_chain header", "invalid_client_attestation");
	let trusted: Result<TrustedClientAttester>;
	try {
		trusted = await runOperation(
			(signal) =>
				options.getAttester(input.data.iss, structuredClone(decoded.value.header), signal),
			options,
		);
	} catch {
		return err({
			code: FederationErrorCode.ServerError,
			description: "Attester trust establishment failed or was cancelled",
		});
	}
	if (!trusted.ok) return trusted;
	let attester: TrustedClientAttester;
	try {
		attester = structuredClone(trusted.value);
	} catch {
		return failure("Invalid attester evidence");
	}
	if (
		attester.expiresAt !== undefined &&
		(!Number.isFinite(attester.expiresAt) || attester.expiresAt <= nowSeconds(options.clock))
	)
		return failure("Attester trust has expired");

	const checked = await verifyToken(
		jwt,
		attester.jwks,
		"oauth-client-attestation+jwt",
		options,
		audience === undefined ? undefined : options.expectedAudience,
		false,
		options.allowedAttestationAlgorithms,
	);
	if (!checked.ok)
		return input.data.exp + skew <= nowSeconds(options.clock)
			? failure("Client Attestation expired during verification", "use_fresh_attestation")
			: invalidCredential(checked.error);
	safeLogger(options?.logger)?.info("Client Attestation verification completed");
	if (
		options.signal?.aborted ||
		(attester.expiresAt !== undefined && attester.expiresAt <= nowSeconds(options.clock))
	)
		return failure("Attester trust or attestation expired during verification");
	if (input.data.exp + skew <= nowSeconds(options.clock))
		return failure("Client Attestation expired during verification", "use_fresh_attestation");
	return ok({
		attestation: input.data,
		attester,
		expiresAt: Math.min(input.data.exp + skew, attester.expiresAt ?? Infinity),
	});
}

async function authenticateClientAttestationImpl(
	attestationJwt: string,
	popJwt: string,
	options: AuthenticateClientAttestationOptions,
): Promise<Result<VerifiedClientAttestation, ClientAttestationError>> {
	safeLogger(options?.logger)?.debug("Authenticating a Client with Client Attestation PoP");

	const maxAge =
		(options.freshness?.mode === "iat" ? options.freshness.maxAgeSeconds : undefined) ??
		options.maxProofAgeSeconds ??
		300;
	const replay =
		options.replay ??
		(options.replayStore ? { mode: "jti" as const, store: options.replayStore } : undefined);
	const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	try {
		entityId(options.audience);
	} catch {
		safeLogger(options?.logger)?.warn(
			"Client Attestation PoP requires a valid authorization server audience",
		);
		return failure("Expected authorization server audience must be a valid issuer identifier");
	}
	if (!replay)
		safeLogger(options.logger)?.warn(
			"Provide a replayStore for Client Attestation PoP replay protection",
		);
	if (typeof options.acceptClient !== "function")
		safeLogger(options.logger)?.warn("Provide acceptClient to decide whether to accept the client");
	if (
		!Number.isFinite(maxAge) ||
		maxAge <= 0 ||
		!Number.isFinite(skew) ||
		skew < 0 ||
		!replay ||
		(options.freshness !== undefined && !["iat", "challenge"].includes(options.freshness.mode)) ||
		(replay !== undefined && !["jti", "challenge", "freshness-only"].includes(replay.mode)) ||
		(replay?.mode === "challenge" && typeof replay.consume !== "function") ||
		(replay?.mode === "jti" && typeof replay.store?.useJti !== "function") ||
		(options.replay !== undefined && options.replayStore !== undefined) ||
		(options.freshness !== undefined && options.maxProofAgeSeconds !== undefined) ||
		typeof options.acceptClient !== "function" ||
		!options.audience ||
		(options.expectedChallenge !== undefined &&
			(typeof options.expectedChallenge !== "string" ||
				options.expectedChallenge.trim().length === 0))
	)
		return failure("Invalid client authentication configuration");

	const parsed = decodeToken(popJwt, options);
	if (!parsed.ok) return invalidCredential(parsed.error);
	const header = checkProtocolHeader(
		parsed.value.header,
		"oauth-client-attestation-pop+jwt",
		options.allowedProofAlgorithms,
	);
	if (!header.ok) return invalidCredential(header.error);
	const proof = PopSchema.safeParse(parsed.value.payload);
	if (!proof.success)
		return failure("Invalid attestation proof claims", "invalid_client_attestation");
	const claims = proof.data;
	// These unverified fields may reject a request early; acceptance still requires both signatures.
	const decodedAttestation = decodeToken(attestationJwt, options);
	if (!decodedAttestation.ok) return invalidCredential(decodedAttestation.error);
	const attestationInput = AttestationSchema.safeParse(decodedAttestation.value.payload);
	if (!attestationInput.success)
		return failure("Invalid Client Attestation claims", "invalid_client_attestation");
	const attestation = attestationInput.data;
	if (
		claims.iss !== attestation.sub ||
		(options.clientId !== undefined && options.clientId !== claims.iss)
	)
		return failure("Client identifiers do not match", "invalid_client_attestation");
	if (options.expectedChallenge !== undefined && claims.challenge !== options.expectedChallenge)
		return failure("Client challenge does not match", "use_attestation_challenge");
	let freshnessStart = claims.iat;
	let freshnessEnd = claims.iat + maxAge;
	if (options.freshness?.mode === "challenge") {
		if (claims.challenge === undefined)
			return failure("A server challenge is required", "use_attestation_challenge");
		try {
			const verifier = options.freshness.verify;
			const challengeValue = claims.challenge;
			const challenge = await runOperation((signal) => verifier(challengeValue, signal), options);
			if (!challenge.ok)
				return challenge.error.code === FederationErrorCode.ServerError
					? challenge
					: failure("Invalid server challenge", "use_attestation_challenge");
			if (
				!Number.isFinite(challenge.value.issuedAt) ||
				!Number.isFinite(challenge.value.expiresAt) ||
				challenge.value.expiresAt <= challenge.value.issuedAt
			)
				return failure("Invalid server challenge", "use_attestation_challenge");
			freshnessStart = challenge.value.issuedAt;
			freshnessEnd = challenge.value.expiresAt;
		} catch {
			return err({
				code: FederationErrorCode.ServerError,
				description: "Challenge verification failed or timed out",
			});
		}
	}
	const attestationFresh = () => attestation.exp + skew > nowSeconds(options.clock);
	if (!attestationFresh())
		return failure("Client Attestation has expired", "use_fresh_attestation");
	if (
		options.freshness?.mode === "challenge" &&
		(freshnessStart > nowSeconds(options.clock) + skew ||
			freshnessEnd + skew <= nowSeconds(options.clock))
	)
		return failure(
			"Server challenge is outside its validity interval",
			"use_attestation_challenge",
		);
	const expiresAt = Math.min(freshnessEnd, claims.exp ?? Infinity, attestation.exp) + skew;
	const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
	if (
		!audiences.includes(options.audience) ||
		freshnessStart > nowSeconds(options.clock) + skew ||
		expiresAt <= nowSeconds(options.clock) ||
		(claims.nbf !== undefined && claims.nbf > nowSeconds(options.clock) + skew)
	)
		return failure(
			"Attestation proof audience or freshness check failed",
			"invalid_client_attestation",
		);
	const verified = await verifyClientAttestation(attestationJwt, {
		...options,
		expectedAudience: options.audience,
	});
	if (!verified.ok) return verified;
	const fresh = () =>
		freshnessStart <= nowSeconds(options.clock) + skew &&
		expiresAt > nowSeconds(options.clock) &&
		(verified.value.attester.expiresAt === undefined ||
			verified.value.attester.expiresAt > nowSeconds(options.clock));
	const expired = () =>
		failure(
			"Client authentication expired or was cancelled",
			!attestationFresh()
				? "use_fresh_attestation"
				: options.freshness?.mode === "challenge" &&
						freshnessEnd + skew <= nowSeconds(options.clock)
					? "use_attestation_challenge"
					: undefined,
		);
	if (!fresh()) return expired();
	const checked = await verifyToken(
		popJwt,
		{ keys: [attestation.cnf.jwk] },
		"oauth-client-attestation-pop+jwt",
		options,
		options.audience,
		true,
		options.allowedProofAlgorithms,
	);
	if (!checked.ok) return !attestationFresh() ? expired() : invalidCredential(checked.error);
	const accepted = await invokeVerificationPolicy(
		options.acceptClient,
		verified.value,
		options,
		"Client acceptance",
	);
	if (!accepted.ok) return accepted;
	if (!fresh() || options.signal?.aborted) return expired();
	if (replay.mode !== "freshness-only") {
		const consumed = await invokeVerificationPolicy(
			(_, signal) =>
				replay.mode === "jti"
					? replay.store.useJti({
							issuer: claims.iss,
							audience: options.audience,
							jti: claims.jti,
							expiresAt,
						})
					: claims.challenge === undefined || signal === undefined
						? false
						: replay.consume(claims.challenge, expiresAt, signal),
			undefined,
			options,
			"Client Attestation PoP replay protection",
		);
		if (!consumed.ok)
			return consumed.error.code === FederationErrorCode.ServerError
				? consumed
				: failure("Attestation proof was already used or replay protection could not be completed");
	}

	if (!fresh() || options.signal?.aborted) return expired();
	return ok({ ...verified.value, expiresAt: Math.min(expiresAt, verified.value.expiresAt) });
}

/** Validate the designated PoP key, without tightening received federation JWK Sets. */
async function validateConfirmationKey(key: JWK): Promise<Result<true>> {
	// The set helper checks public material. This local identifier does not alter cnf.jwk.
	const material = preparePublicJwkSet({ keys: [{ ...key, kid: key.kid ?? "confirmation" }] });
	if (!material.ok) return failure("Invalid Client Attestation confirmation key material");
	if (
		(key.use !== undefined && key.use !== "sig") ||
		(key.key_ops !== undefined && !key.key_ops.includes("verify"))
	)
		return failure("Client Attestation confirmation key must permit signature verification");
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
	return failure("Client Attestation confirmation key has no usable signing algorithm");
}

/** ACA §7.2 syntax parsing; authenticate the returned pair before accepting its claims. */
export function parseConcatenatedClientAttestation(
	value: string,
	options: Pick<ClientAttestationOptions, "maxResponseBytes"> = {},
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

/** Create a draft-07 attestation using the caller's trusted attester signing key. */
export async function createClientAttestation(
	issuer: string,
	params: CreateClientAttestationParams,
	signer: JwtSigner,
	options: ClientAttestationOptions = {},
): Promise<Result<string>> {
	try {
		return await createClientAttestationImpl(issuer, params, signer, options);
	} catch {
		return failure("Client Attestation creation failed");
	}
}
/**
 * Verify an attestation against caller-established attester trust and return a Result.
 * This checks the attestation; authenticating its holder also requires the proof-of-possession
 * flow.
 */
export async function verifyClientAttestation(
	jwt: string,
	options: ClientAttestationVerificationOptions,
): Promise<Result<VerifiedClientAttestation, ClientAttestationError>> {
	try {
		return await verifyClientAttestationImpl(jwt, options);
	} catch {
		return failure("Client Attestation verification failed");
	}
}
/**
 * Verify the attestation and proof, enforce configured replay protection, and invoke acceptClient.
 * The host establishes attester trust and decides whether the authenticated client is acceptable.
 */
export async function authenticateClientAttestation(
	attestationJwt: string,
	popJwt: string,
	options: AuthenticateClientAttestationOptions,
): Promise<Result<VerifiedClientAttestation, ClientAttestationError>> {
	try {
		return await authenticateClientAttestationImpl(attestationJwt, popJwt, options);
	} catch {
		return failure("Client authentication failed");
	}
}
export interface CreateClientAttestationProofParams {
	readonly clientId: string;
	readonly audience: string;
	readonly challenge?: string;
	readonly claims?: Readonly<Record<string, unknown>>;
}
/** Each invocation creates a new jti. Reuse the attestation, never its proof. */
export async function createClientAttestationProof(
	params: CreateClientAttestationProofParams,
	signer: JwtSigner,
	options: FederationOptions = {},
): Promise<Result<string>> {
	try {
		entityId(params.audience);
		if (
			!isJsonData(params.claims ?? {}) ||
			Object.keys(params.claims ?? {}).some((key) =>
				["iss", "aud", "iat", "jti", "challenge"].includes(key),
			)
		)
			return failure("Additional claims cannot replace proof claims");
		const now = nowSeconds(options.clock);
		const proof = PopSchema.safeParse({
			...params.claims,
			iss: params.clientId,
			aud: params.audience,
			iat: now,
			jti: crypto.randomUUID(),
			...(params.challenge !== undefined ? { challenge: params.challenge } : {}),
		});
		if (
			!proof.success ||
			(proof.data.exp !== undefined && proof.data.exp <= now) ||
			(proof.data.nbf !== undefined &&
				proof.data.exp !== undefined &&
				proof.data.nbf >= proof.data.exp)
		)
			return failure("Invalid Client Attestation PoP claims");
		return signToken(proof.data, "oauth-client-attestation-pop+jwt", signer, options);
	} catch {
		return failure("Client Attestation PoP creation failed");
	}
}
/** Syntactic serialization only; receivers must authenticate the pair. */
export function serializeClientAttestation(attestationJwt: string, popJwt: string): Result<string> {
	const checked = parseConcatenatedClientAttestation(`${attestationJwt}~${popJwt}`);
	return checked.ok ? ok(`${attestationJwt}~${popJwt}`) : checked;
}
/** Construct attestation authentication headers after validating the two serialized JWT values. */
export function clientAttestationHeaders(attestationJwt: string, popJwt: string): Result<Headers> {
	const checked = serializeClientAttestation(attestationJwt, popJwt);
	return checked.ok
		? ok(
				new Headers({
					"OAuth-Client-Attestation": attestationJwt,
					"OAuth-Client-Attestation-PoP": popJwt,
				}),
			)
		: checked;
}
/** Fetch Headers combines duplicates; combined values fail the single-JWT grammar. */
export function parseClientAttestationHeaders(
	headers: Headers,
	options: Pick<FederationOptions, "maxResponseBytes"> = {},
): Result<{ attestationJwt: string; popJwt: string }, ClientAttestationError> {
	const attestation = headers.get("OAuth-Client-Attestation"),
		proof = headers.get("OAuth-Client-Attestation-PoP");
	if (!attestation || !proof)
		return failure(
			"Exactly one Client Attestation and PoP header are required",
			"invalid_client_attestation",
		);
	const parsed = parseConcatenatedClientAttestation(`${attestation}~${proof}`, options);
	return parsed.ok ? parsed : invalidCredential(parsed.error);
}
