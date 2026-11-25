import { JwtTyp } from "../constants.js";
import { bindFederationOptions, federationSigningOptions } from "../crypto-context.js";
import { err, type FederationError, type Result } from "../errors.js";
import {
	apiError,
	buildVerifyOpts,
	type VerifyOptions,
	validateExpectedIssuer,
} from "../federation-api/verify-issuer.js";
import { federationEntry } from "../federation-keys.js";
import { signEntityStatement } from "../jose/sign.js";
import { verifyEntityStatement } from "../jose/verify.js";
import { type SignedJwkSetPayload, SignedJwkSetPayloadSchema } from "../schemas/endpoints.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { JWKSet } from "../schemas/jwk.js";
import { assertPositiveTtlSeconds } from "../ttl.js";
import { type BoundFederationOptions, type CryptoContext, entityId, nowSeconds } from "../types.js";
import { prepareProtocolJwkSet } from "./public-material.js";
import { hasConsistentJwkUse, validateJwkSetUseRequirement } from "./use-requirement.js";

export interface SignProtocolJwkSetOptions {
	readonly issuer: string;
	/** The Entity Identifier of the protocol key owner. Defaults to the issuer. */
	readonly owner?: string;
	readonly jwks: JWKSet;
	readonly crypto: CryptoContext;
	readonly options?: BoundFederationOptions;
	readonly issuedAt?: number;
	/** Include exp and use the configured clock for iat if issuedAt is omitted. */
	readonly ttlSeconds?: number;
}

/** Sign one Entity Type's public protocol key set using the issuer's published Federation key. */
export async function signProtocolJwkSet(input: SignProtocolJwkSetOptions): Promise<string> {
	const { crypto, ttlSeconds } = input;
	const options = bindFederationOptions(crypto, input.options);
	const issuer = entityId(input.issuer);
	const owner = input.owner === undefined ? issuer : entityId(input.owner);
	const prepared = prepareProtocolJwkSet(input.jwks, options.algorithmRegistry);
	if (!prepared.ok) throw new TypeError(prepared.error.description);
	const { keys } = prepared.value;
	if (!keys.every(hasConsistentJwkUse))
		throw new TypeError("Protocol JWK use and key_ops must be consistent");
	const use = validateJwkSetUseRequirement(keys, options.algorithmRegistry);
	if (!use.ok) throw new TypeError(use.error.description);

	const claims: Record<string, unknown> = { iss: issuer, sub: owner, keys };
	if (input.issuedAt !== undefined) claims.iat = input.issuedAt;
	if (ttlSeconds !== undefined) {
		assertPositiveTtlSeconds(ttlSeconds, "ttlSeconds", "finite");
		const iat = input.issuedAt ?? nowSeconds(options.clock);
		const exp = iat + ttlSeconds;
		if (!Number.isFinite(iat) || !Number.isFinite(exp) || exp <= iat)
			throw new TypeError("Signed protocol JWKS expiry must be finite and after issuance");
		claims.iat = iat;
		claims.exp = exp;
	}
	const payload = SignedJwkSetPayloadSchema.parse(claims);
	const artifact = "signed-protocol-jwks";
	const keySet = await federationEntry(crypto, { artifact, issuer, subject: owner });
	return signEntityStatement(payload, keySet, {
		...federationSigningOptions(options, artifact),
		typ: JwtTyp.JwkSet,
	});
}

export interface VerifySignedJwkSetOptions extends VerifyOptions {
	/** Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. */
	expectedOwner: string;
}

/**
 * Verify and validate a Signed JWK Set JWT (returned by signed_jwks_uri).
 * Checks typ=jwk-set+jwt, signature, and required payload claims (iss, sub, keys).
 */
export async function verifySignedJwkSet(
	jwt: string,
	signerJwks: JWKSet,
	options: VerifySignedJwkSetOptions,
): Promise<Result<SignedJwkSetPayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (!EntityIdSchema.safeParse(options?.expectedOwner).success)
		return err(apiError("A valid expectedOwner is required"));
	const result = await verifyEntityStatement(
		jwt,
		signerJwks,
		buildVerifyOpts(JwtTyp.JwkSet, options, "signed-protocol-jwks"),
	);
	if (!result.ok) return result;

	const parsed = SignedJwkSetPayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid signed JWK Set payload: ${parsed.error.message}`));
	}
	const useResult = validateJwkSetUseRequirement(parsed.data.keys, options.algorithmRegistry);
	if (!useResult.ok) return useResult;
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	if (parsed.data.sub !== options.expectedOwner)
		return err(apiError("Signed JWK Set owner does not match expectedOwner"));
	return { ok: true, value: parsed.data };
}
