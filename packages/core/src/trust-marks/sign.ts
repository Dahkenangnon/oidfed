import { isJsonData, setOwn } from "../callbacks.js";
import { DEFAULT_DELEGATION_TTL_SECONDS, JwtTyp } from "../constants.js";
import { signEntityStatement } from "../jose/sign.js";
import type { JwtSigner } from "../jose/signer.js";
import { TrustMarkDelegationPayloadSchema, TrustMarkPayloadSchema } from "../schemas/trust-mark.js";
import { assertPositiveTtlSeconds } from "../ttl.js";
import { type Clock, nowSeconds } from "../types.js";
import { checkTrustMarkProfile, type TrustMarkProfile } from "./profiles.js";

export interface TrustMarkLifetime {
	readonly ttlSeconds?: number;
	readonly noExpiry?: boolean;
}
export interface SignTrustMarkDelegationOptions extends TrustMarkLifetime {
	readonly issuer: string;
	readonly subject: string;
	readonly trustMarkType: string;
	readonly signer: JwtSigner;
	readonly clock?: Clock;
	readonly ref?: string;
	readonly additionalClaims?: Readonly<Record<string, unknown>>;
}
export interface SignTrustMarkOptions extends SignTrustMarkDelegationOptions {
	readonly logoUri?: string;
	readonly delegation?: string;
	readonly typ?: string;
	readonly trustMarkProfiles?: readonly TrustMarkProfile[];
}

function payloadFor(options: SignTrustMarkDelegationOptions): Record<string, unknown> {
	if (!options.trustMarkType) throw new TypeError("A Trust Mark type is required");
	const iat = nowSeconds(options.clock);
	if (!Number.isFinite(iat)) throw new TypeError("Issuance time must be finite");
	if (options.noExpiry !== undefined && typeof options.noExpiry !== "boolean")
		throw new TypeError("noExpiry must be a boolean");
	if (options.noExpiry && options.ttlSeconds !== undefined)
		throw new TypeError("noExpiry and ttlSeconds conflict");
	const ttl = options.ttlSeconds ?? DEFAULT_DELEGATION_TTL_SECONDS;
	assertPositiveTtlSeconds(ttl, "ttlSeconds", "finite");
	if (!Number.isFinite(iat + ttl)) throw new TypeError("ttlSeconds must be positive and finite");
	const payload: Record<string, unknown> = {
		iss: options.issuer,
		sub: options.subject,
		trust_mark_type: options.trustMarkType,
		iat,
	};
	if (!options.noExpiry) payload.exp = iat + ttl;
	if (options.ref !== undefined) payload.ref = options.ref;
	const extra = options.additionalClaims;
	if (extra !== undefined) {
		if (!extra || typeof extra !== "object" || Array.isArray(extra) || !isJsonData(extra))
			throw new TypeError("Additional claims must be JSON object data");
		const reserved = new Set([
			"iss",
			"sub",
			"trust_mark_type",
			"iat",
			"exp",
			"logo_uri",
			"ref",
			"delegation",
		]);
		for (const [name, value] of Object.entries(extra)) {
			if (reserved.has(name)) throw new TypeError(`Additional claim '${name}' is reserved`);
			setOwn(payload, name, structuredClone(value));
		}
	}
	return payload;
}

/** Sign a Trust Mark without starting an issuer server. Accreditation is host policy. */
export async function signTrustMark(options: SignTrustMarkOptions): Promise<string> {
	const payload = payloadFor(options);
	if (options.logoUri !== undefined) payload.logo_uri = options.logoUri;
	if (options.delegation !== undefined) payload.delegation = options.delegation;
	TrustMarkPayloadSchema.parse(payload);
	const typ = options.typ ?? JwtTyp.TrustMark;
	const profile = await checkTrustMarkProfile(typ, payload, options.trustMarkProfiles);
	if (!profile.ok) throw new TypeError(profile.error.description);
	return signEntityStatement(payload, options.signer, { typ });
}

/** Owner-signed issuance authorization. The base delegation typ cannot be overridden. */
export async function signTrustMarkDelegation(
	options: SignTrustMarkDelegationOptions,
): Promise<string> {
	const payload = payloadFor(options);
	TrustMarkDelegationPayloadSchema.parse(payload);
	return signEntityStatement(payload, options.signer, { typ: JwtTyp.TrustMarkDelegation });
}

export type TrustMarkDelegationIssuanceOptions = Omit<
	SignTrustMarkDelegationOptions,
	"issuer" | "subject" | "trustMarkType" | "signer" | "clock"
>;
