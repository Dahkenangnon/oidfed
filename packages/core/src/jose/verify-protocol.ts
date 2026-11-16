/** Protocol JWT verification using separately resolved keys and explicit caller expectations. */

import * as jose from "jose";
import { DEFAULT_CLOCK_SKEW_SECONDS, InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { type JWKSet, MetadataJWKSetSchema } from "../schemas/jwk.js";
import type { Clock } from "../types.js";
import { isValidAlgorithm } from "./keys.js";

export interface VerifyProtocolJwtOptions {
	expectedTyp: string;
	/** Application policy, in addition to supported asymmetric algorithms. */
	allowedAlgorithms?: readonly string[];
	/** Require kid by default; single-key permits omission for a set containing one key. */
	keyIdPolicy?: "required" | "single-key";
	clockSkewSeconds?: number;
	clock?: Clock;
}

export interface VerifiedProtocolJwt {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
}

/**
 * Verify a protocol JWT against authenticated public metadata keys.
 * Checks signature, type and JWT time claims. The caller validates protocol claims
 * such as issuer and audience and supplies keys bound to the expected entity.
 */
export async function verifyProtocolJwt(
	jwt: string,
	jwks: JWKSet,
	options: VerifyProtocolJwtOptions,
): Promise<Result<VerifiedProtocolJwt, FederationError>> {
	try {
		const header = jose.decodeProtectedHeader(jwt);
		if (header.typ !== options.expectedTyp) {
			return err({
				code: InternalErrorCode.SignatureInvalid,
				description: `Invalid typ header: expected '${options.expectedTyp}'`,
			});
		}
		if (
			!isValidAlgorithm(header.alg) ||
			(options.allowedAlgorithms !== undefined && !options.allowedAlgorithms.includes(header.alg))
		) {
			return err({
				code: InternalErrorCode.UnsupportedAlg,
				description: "Unsupported protocol JWT signing algorithm",
			});
		}
		const parsed = MetadataJWKSetSchema.safeParse(jwks);
		if (!parsed.success) {
			return err({
				code: InternalErrorCode.SignatureInvalid,
				description: "Invalid public protocol key set",
			});
		}
		// OIDC Core §10.1 requires a header kid when the published set has multiple keys.
		// Count the original set before filtering candidates by algorithm or usage.
		const mayOmitKid = options.keyIdPolicy === "single-key" && parsed.data.keys.length === 1;
		if (
			(header.kid === undefined && !mayOmitKid) ||
			(header.kid !== undefined && (typeof header.kid !== "string" || !header.kid))
		) {
			return err({
				code: InternalErrorCode.SignatureInvalid,
				description: "Missing or invalid kid header",
			});
		}

		const verificationOptions: jose.JWTVerifyOptions = {
			algorithms: [header.alg],
			typ: options.expectedTyp,
			clockTolerance: options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS,
			...(options.clock ? { currentDate: new Date(options.clock.now() * 1_000) } : {}),
		};
		// Filter only after the published cardinality check; omitted kid must not become valid.
		const keys = jose.createLocalJWKSet({
			keys: parsed.data.keys.filter((key) => ["RSA", "EC", "OKP"].includes(key.kty)),
		} as jose.JSONWebKeySet);
		try {
			const verified = await jose.jwtVerify(jwt, keys, verificationOptions);
			return ok({ header: verified.protectedHeader, payload: verified.payload });
		} catch (cause) {
			if (!(cause instanceof jose.errors.JWKSMultipleMatchingKeys)) throw cause;
			// RFC 7517 §4.5 permits shared identifiers. JOSE filters these candidates by
			// kid, algorithm, key type, curve and signing usage; each still needs verification.
			for await (const key of cause) {
				// RSA keys can import below JWA's 2048-bit minimum (§3.3 and §3.5).
				// Skip those candidates per RFC 7517 §5 before attempting verification.
				if (
					"modulusLength" in key.algorithm &&
					typeof key.algorithm.modulusLength === "number" &&
					key.algorithm.modulusLength < 2048
				) {
					continue;
				}
				try {
					const verified = await jose.jwtVerify(jwt, key, verificationOptions);
					return ok({ header: verified.protectedHeader, payload: verified.payload });
				} catch (error) {
					if (!(error instanceof jose.errors.JWSSignatureVerificationFailed)) throw error;
				}
			}
			throw cause;
		}
	} catch (cause) {
		return err({
			code: InternalErrorCode.SignatureInvalid,
			description: "Protocol JWT signature or claims could not be verified",
			cause,
		});
	}
}
