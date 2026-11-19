/** JWT policy and verification shared by Federation and application protocol profiles. */
import {
	assertSigningPublicJwk,
	assertVerificationKey,
	CLASSICAL_ALGORITHMS,
	type CryptoEngine,
	CryptoError,
	type Jwk,
	type JwkSet,
	type JwsAlgorithmRegistry,
	jwsSignatureRules,
	type KeyringEntry,
	parseCompactJws,
	signCompactJws,
	toPublicJwk,
} from "@oidfed/crypto";
import { DEFAULT_CLOCK_SKEW_SECONDS, InternalErrorCode } from "./constants.js";
import { err, type FederationError, ok, type Result } from "./errors.js";
import { JWKSchema } from "./schemas/jwk.js";
import { type Clock, InvalidClockError, nowSeconds } from "./types.js";

/** Expected type semantics. Media-type comparison permits the application/ prefix. */
export type JwtTypeRule =
	| "absent"
	| "any"
	| {
			readonly expected: string;
			readonly comparison?: "exact" | "media-type";
			readonly allowAbsent?: boolean;
	  };
/** Rules for a token family; callers still validate protocol claims and key provenance. */
export interface JwtVerificationProfile {
	/** Header type rule for this token family; absence is an explicit choice. */
	readonly typ: JwtTypeRule;
	/** Header identifier policy, including narrowly scoped single-key and confirmation-key handling. */
	readonly keyId: "required" | "allow-single-key" | "allow-missing" | "confirmation-key";
	/** Expected recipient and whether additional audience members are permitted. */
	readonly audience?: { readonly expected: string; readonly mode: "contains" | "only" };
}
/** Explicit backend and deployment policy. Per-call policy can only narrow this configuration. */
export interface JwsServiceOptions {
	/** Host-owned public cryptographic operations; never inferred from runtime globals. */
	readonly engine: CryptoEngine;
	/** Unix-second clock; defaults to the current time and must remain finite. */
	readonly clock?: Clock;
	/** Nonnegative tolerance for expiration and not-before checks; defaults to 60 seconds. */
	readonly clockSkewSeconds?: number;
	/** Deployment acceptance policy, intersected with engine capability and call policy. */
	readonly allowedAlgorithms?: readonly string[];
	readonly algorithmRegistry?: JwsAlgorithmRegistry | undefined;
	/** Compact token size bound, defaulting to the crypto package limit. */
	readonly maxCompactBytes?: number | undefined;
	/** Maximum eligible keys attempted for one token; defaults to 16. */
	readonly maxVerificationCandidates?: number;
	/** Cancellation signal checked before and after backend verification. */
	readonly signal?: AbortSignal;
}
/** Authenticated header and claims; protocol-specific checks may still be required. */
export interface VerifiedJwt {
	readonly header: Record<string, unknown>;
	readonly payload: Record<string, unknown>;
}

/** JWT service with no built-in backend or private-key storage. */
export class JwsService {
	private readonly maximum: number;
	private readonly algorithms: readonly string[];
	private readonly options: Readonly<JwsServiceOptions>;
	constructor(options: JwsServiceOptions) {
		this.options = Object.freeze({ ...options });
		if (!options.engine || typeof options.engine.verify !== "function")
			throw new TypeError("A CryptoEngine is required");
		this.maximum = options.maxVerificationCandidates ?? 16;
		if (!Number.isSafeInteger(this.maximum) || this.maximum <= 0)
			throw new RangeError("maxVerificationCandidates must be a positive safe integer");
		this.algorithms = Object.freeze([...(options.allowedAlgorithms ?? CLASSICAL_ALGORITHMS)]);
	}
	/** Sign with the supplied immutable snapshot; never resolve a second current key. */
	async signJwt(
		entry: KeyringEntry,
		payload: Record<string, unknown>,
		header: Readonly<Record<string, unknown>> = {},
	): Promise<string> {
		const identity = assertSigningPublicJwk(entry.signer.publicJwk, this.options.algorithmRegistry);
		if (!this.algorithms.includes(identity.alg))
			throw new CryptoError("UNSUPPORTED_ALGORITHM", "Signing algorithm is not allowed");
		return signCompactJws(
			payload,
			{
				...header,
				alg: identity.alg,
				kid: identity.kid,
			},
			entry.signer,
			{ maxBytes: this.options.maxCompactBytes, algorithmRegistry: this.options.algorithmRegistry },
		);
	}
	/** Verify exact encoded bytes, then validate JWT dates, type and audience. */
	async verifyJwt(
		token: string,
		jwks: JwkSet,
		profile: JwtVerificationProfile,
		call: { readonly allowedAlgorithms?: readonly string[] } = {},
	): Promise<Result<VerifiedJwt>> {
		let parsedSuccessfully = false;
		try {
			const parsed = parseCompactJws(token, {
				maxBytes: this.options.maxCompactBytes,
				algorithmRegistry: this.options.algorithmRegistry,
			});
			parsedSuccessfully = true;
			const { header, payload } = parsed;
			if (
				!this.algorithms.includes(header.alg) ||
				!this.options.engine.algorithms.includes(header.alg) ||
				(call.allowedAlgorithms !== undefined && !call.allowedAlgorithms.includes(header.alg))
			)
				return failure(
					InternalErrorCode.UnsupportedAlg,
					"JWT signing algorithm is not allowed or supported",
				);
			if (!matchesType(header.typ, profile.typ))
				return failure(InternalErrorCode.SignatureInvalid, "Invalid typ header");
			if (!jwks || !Array.isArray(jwks.keys))
				return failure(InternalErrorCode.SignatureInvalid, "Invalid public key set");
			if (
				header.kid === undefined &&
				(profile.keyId === "required" ||
					(profile.keyId === "allow-single-key" && jwks.keys.length !== 1))
			)
				return failure(InternalErrorCode.SignatureInvalid, "Missing or invalid kid header");
			let attempted = 0;
			for (const key of jwks.keys as readonly Jwk[]) {
				if (!JWKSchema.safeParse(key).success) continue;
				if (
					header.kid !== undefined &&
					key.kid !== header.kid &&
					!(profile.keyId === "confirmation-key" && jwks.keys.length === 1 && key.kid === undefined)
				)
					continue;
				let publicKey: Jwk;
				try {
					publicKey = toPublicJwk(
						assertVerificationKey(key, header.alg, this.options.algorithmRegistry),
						this.options.algorithmRegistry,
					);
				} catch (cause) {
					if (
						cause instanceof CryptoError &&
						["MALFORMED_KEY", "UNSUPPORTED_ALGORITHM"].includes(cause.code)
					)
						continue;
					throw cause;
				}
				if (
					!jwsSignatureRules(publicKey, header.alg, this.options.algorithmRegistry).accepts(
						parsed.signature,
					)
				)
					continue;
				if (++attempted > this.maximum)
					return failure(
						InternalErrorCode.SignatureInvalid,
						"JWT verification candidate limit exceeded",
					);
				if (this.options.signal?.aborted)
					return failure(InternalErrorCode.SignatureInvalid, "Operation cancelled");
				let verified: boolean;
				try {
					verified = await this.options.engine.verify({
						algorithm: header.alg,
						key: publicKey,
						signingInput: parsed.signingInput,
						signature: parsed.signature,
					});
				} catch (cause) {
					if (cause instanceof CryptoError && cause.code === "MALFORMED_KEY") continue;
					throw cause;
				}
				if (typeof verified !== "boolean")
					throw new CryptoError(
						"ENGINE_CONTRACT_VIOLATION",
						"Verification must return a literal boolean",
					);
				if (verified !== true) continue;
				const time = checkTime(payload, this.options);
				if (time) return time;
				if (this.options.signal?.aborted)
					return failure(InternalErrorCode.SignatureInvalid, "Operation cancelled");
				if (profile.audience && !matchesAudience(payload.aud, profile.audience))
					return failure(InternalErrorCode.SignatureInvalid, "Invalid JWT audience");
				return ok({ header, payload });
			}
			return failure(InternalErrorCode.SignatureInvalid, "JWT signature could not be verified");
		} catch (cause) {
			if (cause instanceof InvalidClockError)
				return failure(InternalErrorCode.InvalidClock, cause.message, cause);
			if (
				!parsedSuccessfully &&
				cause instanceof CryptoError &&
				cause.code === "UNSUPPORTED_ALGORITHM"
			)
				return failure(InternalErrorCode.UnsupportedAlg, cause.message, cause);
			if (
				!(cause instanceof CryptoError) ||
				!["MALFORMED_JWS", "MALFORMED_KEY"].includes(cause.code)
			)
				return failure(
					InternalErrorCode.CryptoOperationFailed,
					"Cryptographic operation failed",
					cause,
				);
			return failure(
				InternalErrorCode.SignatureInvalid,
				"JWT signature or claims could not be verified",
				cause,
			);
		}
	}
}
function failure(
	code: FederationError["code"],
	description: string,
	cause?: unknown,
): Result<never> {
	return err({ code, description, ...(cause === undefined ? {} : { cause }) });
}
function matchesType(actual: unknown, rule: JwtTypeRule): boolean {
	if (rule === "any") return true;
	if (rule === "absent") return actual === undefined;
	if (actual === undefined && rule.allowAbsent) return true;
	if (typeof actual !== "string") return false;
	if (rule.comparison !== "media-type") return actual === rule.expected;
	const media = (value: string) =>
		value.includes("/") ? value.toLowerCase() : `application/${value.toLowerCase()}`;
	return media(actual) === media(rule.expected);
}
function matchesAudience(
	actual: unknown,
	rule: NonNullable<JwtVerificationProfile["audience"]>,
): boolean {
	if (typeof actual === "string") return actual === rule.expected;
	return (
		Array.isArray(actual) &&
		actual.every((value) => typeof value === "string") &&
		actual.includes(rule.expected) &&
		(rule.mode !== "only" || actual.length === 1)
	);
}
function checkTime(
	payload: Record<string, unknown>,
	options: JwsServiceOptions,
): Result<never> | undefined {
	const now = nowSeconds(options.clock);
	const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	if (!Number.isFinite(now) || !Number.isFinite(skew) || skew < 0)
		return failure(
			InternalErrorCode.InvalidClock,
			"JWT validation requires a finite clock and nonnegative tolerance",
		);
	for (const name of ["iat", "nbf", "exp"]) {
		const value = payload[name];
		if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value)))
			return failure(InternalErrorCode.SignatureInvalid, "JWT dates must be finite NumericDates");
	}
	if (typeof payload.exp === "number" && payload.exp <= now - skew)
		return failure(InternalErrorCode.Expired, "JWT has expired");
	if (typeof payload.nbf === "number" && payload.nbf > now + skew)
		return failure(InternalErrorCode.SignatureInvalid, "JWT is not yet valid");
	return undefined;
}
