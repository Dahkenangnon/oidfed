/** Trust Mark and owner-delegation signature, claim, and authorization checks. */

import { freezeSnapshot } from "../callbacks.js";
import { DEFAULT_CLOCK_SKEW_SECONDS, InternalErrorCode, JwtTyp } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { isValidAlgorithm } from "../jose/keys.js";
import { decodeEntityStatement, verifyEntityStatement } from "../jose/verify.js";
import { safeLogger } from "./../logging.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { JWKSet } from "../schemas/jwk.js";
import {
	TrustMarkDelegationPayloadSchema,
	type TrustMarkOwner,
	TrustMarkOwnerSchema,
	TrustMarkPayloadSchema,
} from "../schemas/trust-mark.js";
import {
	type Clock,
	type FederationOptions,
	nowSeconds,
	type TrustMarkEvidence,
	type ValidatedTrustMarkDelegation,
} from "../types.js";
import { checkTrustMarkProfile } from "./profiles.js";

export interface TrustMarkValidationOptions extends FederationOptions {
	trustMarkOwners?: Record<string, TrustMarkOwner>;
	/** Entity whose configuration contains this mark; supply independently of the JWT (§7.3). */
	expectedSubject: string;
	expectedTrustMarkType?: string;
}

function tmError(description: string): FederationError {
	return { code: InternalErrorCode.TrustMarkInvalid, description };
}

function describeSchemaIssues(
	issues: ReadonlyArray<{ path: readonly PropertyKey[]; message: string }>,
) {
	return issues
		.map((issue) => {
			const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "payload";
			return `${path}: ${issue.message}`;
		})
		.join("; ");
}

/**
 * Verify a mark's signature, claims, issuer authorization, and required owner delegation.
 * The caller supplies trusted issuer keys and the applicable anchor policy.
 */
export async function validateTrustMark(
	trustMarkJwt: string,
	trustMarkIssuers: Record<string, string[]>,
	issuerJwks: JWKSet,
	options: TrustMarkValidationOptions,
): Promise<Result<TrustMarkEvidence, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting validate trust mark");

	if (!EntityIdSchema.safeParse(options?.expectedSubject).success)
		return err(tmError("A valid expectedSubject is required"));
	const clockSkew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	const now = nowSeconds(options?.clock);

	const decoded = decodeEntityStatement(trustMarkJwt);
	if (!decoded.ok)
		return err(tmError(`Failed to decode trust mark JWT: ${decoded.error.description}`));

	const { header, payload } = decoded.value;

	const alg = header.alg as string | undefined;
	if (!isValidAlgorithm(alg)) {
		return err(tmError(`Unsupported algorithm: '${String(alg)}'`));
	}

	if (!header.kid) {
		return err(tmError("Trust Mark JWT must include kid header parameter"));
	}

	const parsedPayload = TrustMarkPayloadSchema.safeParse(payload);
	if (!parsedPayload.success) {
		return err(
			tmError(`Invalid Trust Mark payload: ${describeSchemaIssues(parsedPayload.error.issues)}`),
		);
	}
	const p = parsedPayload.data;
	const iss = p.iss;
	const sub = p.sub;
	const trustMarkType = p.trust_mark_type;
	const iat = p.iat;
	if (
		options.expectedTrustMarkType !== undefined &&
		trustMarkType !== options.expectedTrustMarkType
	)
		return err(tmError("Trust Mark type does not match expectation"));
	const profile = await checkTrustMarkProfile(
		header.typ,
		payload,
		options.trustMarkProfiles,
		false,
	);
	if (!profile.ok) return profile;

	if (sub !== options.expectedSubject) {
		return err(tmError("Trust mark sub does not match expected entity"));
	}

	// Federation §3.1.2 assigns authorization to explicit JSON members.
	if (!Object.hasOwn(trustMarkIssuers, trustMarkType)) {
		return err(tmError("Trust mark type not recognized"));
	}
	const allowedIssuers = trustMarkIssuers[trustMarkType];
	if (
		!Array.isArray(allowedIssuers) ||
		!allowedIssuers.every((issuer) => typeof issuer === "string")
	) {
		return err(tmError("Trust mark issuer entry must be an array of Entity Identifiers"));
	}
	// Empty array = anyone may issue
	if (allowedIssuers.length > 0 && !allowedIssuers.includes(iss)) {
		return err(tmError("Issuer is not authorized for this trust mark type"));
	}

	const verifyOpts: { clockSkewSeconds: number; expectedTyp: string; clock?: Clock } = {
		clockSkewSeconds: clockSkew,
		expectedTyp: header.typ as string,
	};
	if (options?.clock) verifyOpts.clock = options.clock;
	const verifyResult = await verifyEntityStatement(trustMarkJwt, issuerJwks, verifyOpts);
	if (!verifyResult.ok) {
		return err(tmError(`Signature verification failed: ${verifyResult.error.description}`));
	}

	if (iat > now + clockSkew) {
		return err(tmError(`iat is in the future: ${iat}`));
	}

	const exp = p.exp;
	if (exp !== undefined && exp <= now - clockSkew) {
		return err(tmError(`Trust mark has expired: exp=${exp}`));
	}

	// Delegation is mandatory when the TA lists this type in trust_mark_owners
	const delegationJwt = p.delegation;
	const owner = trustMarkOwner(options?.trustMarkOwners, trustMarkType);
	if (!owner.ok) return owner;
	if (owner.value !== undefined && delegationJwt === undefined) {
		return err(
			tmError(
				`Trust mark type '${trustMarkType}' requires delegation (in trust_mark_owners) but none provided`,
			),
		);
	}

	let delegation: ValidatedTrustMarkDelegation | undefined;
	if (delegationJwt !== undefined) {
		const delegationResult = await validateDelegation(
			delegationJwt,
			iss,
			trustMarkType,
			options,
			now,
			clockSkew,
		);
		if (!delegationResult.ok) return delegationResult;
		delegation = delegationResult.value;
	}

	const profileClaims = await checkTrustMarkProfile(header.typ, payload, options.trustMarkProfiles);
	if (!profileClaims.ok) return profileClaims;
	const deadline = Math.min(exp ?? Infinity, delegation?.expiresAt ?? Infinity);
	const validated: TrustMarkEvidence = {
		jwt: trustMarkJwt,
		claims: freezeSnapshot(structuredClone(payload)),
		verificationKey: { source: "current", kid: header.kid as string },
		...(Number.isFinite(deadline) ? { verificationExpiresAt: deadline } : {}),
		trustMarkType,
		issuer: iss,
		subject: sub,
		issuedAt: iat,
		...(exp !== undefined ? { expiresAt: exp } : {}),
		...(delegation !== undefined ? { delegation } : {}),
	};
	return ok(freezeSnapshot(validated));
}

async function validateDelegation(
	delegationJwt: string,
	trustMarkIssuer: string,
	trustMarkType: string,
	options: TrustMarkValidationOptions | undefined,
	now: number,
	clockSkew: number,
): Promise<Result<ValidatedTrustMarkDelegation, FederationError>> {
	const decoded = decodeEntityStatement(delegationJwt);
	if (!decoded.ok)
		return err(tmError(`Failed to decode delegation JWT: ${decoded.error.description}`));

	const { header, payload } = decoded.value;

	if (header.typ !== JwtTyp.TrustMarkDelegation) {
		return err(
			tmError(
				`Invalid delegation typ: expected '${JwtTyp.TrustMarkDelegation}', got '${String(header.typ)}'`,
			),
		);
	}

	if (!header.kid) {
		return err(tmError("Trust Mark delegation JWT must include kid header parameter"));
	}

	const dAlg = header.alg as string | undefined;
	if (!isValidAlgorithm(dAlg)) {
		return err(tmError(`Unsupported delegation algorithm: '${String(dAlg)}'`));
	}

	const parsedPayload = TrustMarkDelegationPayloadSchema.safeParse(payload);
	if (!parsedPayload.success) {
		return err(
			tmError(
				`Invalid Trust Mark delegation payload: ${describeSchemaIssues(parsedPayload.error.issues)}`,
			),
		);
	}
	const dp = parsedPayload.data;
	const dIss = dp.iss;
	const dSub = dp.sub;
	const dTmType = dp.trust_mark_type;
	const dIat = dp.iat;

	if (dSub !== trustMarkIssuer) {
		return err(
			tmError(`Delegation sub '${dSub}' does not match trust mark issuer '${trustMarkIssuer}'`),
		);
	}

	if (dTmType !== trustMarkType) {
		return err(
			tmError(`Delegation trust_mark_type '${dTmType}' does not match '${trustMarkType}'`),
		);
	}

	const configuredOwner = trustMarkOwner(options?.trustMarkOwners, trustMarkType);
	if (!configuredOwner.ok) return configuredOwner;
	if (configuredOwner.value === undefined) {
		return err(tmError(`No trust_mark_owners configured for type '${trustMarkType}'`));
	}

	const owner = configuredOwner.value;

	if (dIss !== owner.sub) {
		return err(
			tmError(`Delegation iss '${dIss}' does not match trust_mark_owners sub '${owner.sub}'`),
		);
	}

	if (dIat > now + clockSkew) {
		return err(tmError(`Delegation iat is in the future: ${dIat}`));
	}

	const dVerifyOpts: { clockSkewSeconds: number; expectedTyp: string; clock?: Clock } = {
		clockSkewSeconds: clockSkew,
		expectedTyp: JwtTyp.TrustMarkDelegation,
	};
	if (options?.clock) dVerifyOpts.clock = options.clock;
	const verifyResult = await verifyEntityStatement(delegationJwt, owner.jwks, dVerifyOpts);
	if (!verifyResult.ok) {
		return err(
			tmError(`Delegation signature verification failed: ${verifyResult.error.description}`),
		);
	}

	const dExp = dp.exp;
	if (dExp !== undefined && dExp <= now - clockSkew) {
		return err(tmError(`Delegation has expired: exp=${dExp}`));
	}

	const validatedDelegation: ValidatedTrustMarkDelegation = {
		issuer: dIss,
		subject: dSub,
		trustMarkType: dTmType,
		issuedAt: dIat,
		...(dExp !== undefined ? { expiresAt: dExp } : {}),
	};
	return ok(validatedDelegation);
}

function trustMarkOwner(
	owners: Record<string, TrustMarkOwner> | undefined,
	type: string,
): Result<TrustMarkOwner | undefined, FederationError> {
	if (!owners || !Object.hasOwn(owners, type)) return ok(undefined);
	const parsed = TrustMarkOwnerSchema.safeParse(owners[type]);
	if (!parsed.success) return err(tmError(`Invalid trust_mark_owners entry for type '${type}'`));
	return ok(parsed.data);
}

export {
	type FetchTrustMarkParams,
	type FetchTrustMarkStatusInput,
	type FetchTrustMarkStatusOptions,
	fetchTrustMark,
	fetchTrustMarkStatus,
	type TrustMarkStatusResult,
} from "./fetch.js";
export { type ValidateTrustMarkLogoOptions, validateTrustMarkLogo } from "./logo.js";
export type { TrustMarkProfile } from "./profiles.js";
export {
	type SignTrustMarkDelegationOptions,
	type SignTrustMarkOptions,
	signTrustMark,
	signTrustMarkDelegation,
	type TrustMarkLifetime,
} from "./sign.js";
