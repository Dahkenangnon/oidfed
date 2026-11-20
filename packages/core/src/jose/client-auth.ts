/** Federation client assertion verification with identity, audience, and replay checks. */

import { runAsyncOperation } from "../async-operation.js";
import { DEFAULT_CLOCK_SKEW_SECONDS } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type { JwsServiceOptions } from "../jws-service.js";
import { JwsService } from "../jws-service.js";
import type { JWKSet } from "../schemas/jwk.js";
import { requireReplayStorage } from "../storage/capabilities.js";
import type { FederationStorage } from "../storage/contracts.js";
import { type Clock, InvalidClockError, nowSeconds } from "../types.js";

export interface VerifiedClientAssertion {
	readonly clientId: string;
	readonly issuedAt?: number;
	readonly expiresAt: number;
	readonly jti: string;
}

/** Verify a `private_key_jwt` client assertion against the client's JWKS and expected audience. */
export async function verifyClientAssertion(
	assertion: string,
	jwks: JWKSet,
	expectedAudience: string,
	options: JwsServiceOptions & {
		clockSkewSeconds?: number;
		clock?: Clock;
		allowedAlgorithms?: readonly string[];
		algorithmRegistry?: import("@oidfed/crypto").JwsAlgorithmRegistry | undefined;
		storage?: FederationStorage | undefined;
		signal?: AbortSignal;
		httpTimeoutMs?: number;
	},
): Promise<Result<VerifiedClientAssertion, FederationError>> {
	try {
		const checked = await new JwsService(options).verifyJwt(assertion, jwks, {
			typ: { expected: "JWT", allowAbsent: true },
			keyId: "allow-single-key",
		});
		if (!checked.ok)
			return checked.error.code === "ERR_EXPIRED"
				? err({ ...checked.error, code: "ERR_SIGNATURE_INVALID" })
				: checked;
		const payload = checked.value.payload as {
			iss?: string;
			sub?: string;
			aud?: unknown;
			exp?: number;
			iat?: number;
			jti?: string;
		};

		if (
			typeof payload.iss !== "string" ||
			!payload.iss ||
			typeof payload.sub !== "string" ||
			payload.iss !== payload.sub
		) {
			return err({
				code: "invalid_client",
				description: `Client assertion 'iss' must equal 'sub': iss='${String(payload.iss)}', sub='${String(payload.sub)}'`,
			});
		}

		const aud = payload.aud;
		if (typeof aud === "string") {
			if (aud !== expectedAudience) {
				return err({
					code: "invalid_client",
					description: `Invalid audience: expected '${expectedAudience}', got '${aud}'`,
				});
			}
		} else if (Array.isArray(aud)) {
			// Spec requires audience to contain only the expected Entity Identifier
			if (aud.length !== 1 || aud[0] !== expectedAudience) {
				return err({
					code: "invalid_client",
					description: `Invalid audience: must contain only '${expectedAudience}', got [${aud.map((a) => `'${a}'`).join(", ")}]`,
				});
			}
		} else {
			return err({
				code: "invalid_client",
				description: "Missing or invalid 'aud' claim",
			});
		}

		const now = nowSeconds(options?.clock);
		const skew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
		if (
			typeof payload.exp !== "number" ||
			!Number.isFinite(payload.exp) ||
			payload.exp + skew <= now ||
			typeof payload.jti !== "string" ||
			!payload.jti
		) {
			return err({ code: "invalid_client", description: "Client assertions require exp and jti" });
		}
		// OIDC Core §9 requires exp and jti; iat is optional.
		if (payload.iat !== undefined && (!Number.isFinite(payload.iat) || payload.iat > now + skew)) {
			return err({ code: "invalid_client", description: "Invalid client assertion issuance time" });
		}
		if (options.storage?.capabilities.includes("replay")) {
			try {
				const replayStore = requireReplayStorage(options.storage, "Client assertion");
				const claim = {
					issuer: payload.iss,
					audience: expectedAudience,
					jti: payload.jti,
					expiresAt: payload.exp + skew,
				};
				const claimed = await runAsyncOperation(() => replayStore.useJti(claim), options);
				if (claimed !== true)
					return err({ code: "invalid_client", description: "Client assertion was already used" });
			} catch (cause) {
				return err({
					code: "server_error",
					description: "Client assertion replay storage failed",
					cause,
				});
			}
		}
		// OIDC Core §9: acceptance must remain within exp, including time spent in replay storage.
		if (options?.signal?.aborted || payload.exp + skew <= nowSeconds(options?.clock))
			return err({
				code: "invalid_client",
				description: "Client assertion expired during verification",
			});
		return ok({
			clientId: payload.iss,
			...(payload.iat !== undefined ? { issuedAt: payload.iat } : {}),
			expiresAt: payload.exp,
			jti: payload.jti,
		});
	} catch (cause) {
		if (cause instanceof InvalidClockError)
			return err({ code: "ERR_INVALID_CLOCK", description: cause.message, cause });
		throw cause;
	}
}
