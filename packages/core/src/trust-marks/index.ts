import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_DELEGATION_TTL_SECONDS,
	InternalErrorCode,
	JwtTyp,
} from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { isValidAlgorithm } from "../jose/keys.js";
import { signEntityStatement } from "../jose/sign.js";
import type { JwtSigner } from "../jose/signer.js";
import { decodeEntityStatement, verifyEntityStatement } from "../jose/verify.js";
import type { JWKSet } from "../schemas/jwk.js";
import {
	TrustMarkDelegationPayloadSchema,
	type TrustMarkOwner,
	TrustMarkPayloadSchema,
} from "../schemas/trust-mark.js";
import type {
	Clock,
	FederationOptions,
	ValidatedTrustMark,
	ValidatedTrustMarkDelegation,
} from "../types.js";
import { nowSeconds } from "../types.js";

export async function signTrustMarkDelegation(params: {
	issuer: string;
	subject: string;
	trustMarkType: string;
	signer: JwtSigner;
	ttlSeconds?: number;
	clock?: Clock;
}): Promise<string> {
	const now = nowSeconds(params.clock);
	const ttl = params.ttlSeconds ?? DEFAULT_DELEGATION_TTL_SECONDS;

	const payload: Record<string, unknown> = {
		iss: params.issuer,
		sub: params.subject,
		trust_mark_type: params.trustMarkType,
		iat: now,
		exp: now + ttl,
	};

	return signEntityStatement(payload, params.signer, {
		typ: JwtTyp.TrustMarkDelegation,
	});
}

interface TrustMarkValidationOptions extends FederationOptions {
	trustMarkOwners?: Record<string, TrustMarkOwner>;
	expectedSubject?: string;
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

export async function validateTrustMark(
	trustMarkJwt: string,
	trustMarkIssuers: Record<string, string[]>,
	issuerJwks: JWKSet,
	options?: TrustMarkValidationOptions,
): Promise<Result<ValidatedTrustMark, FederationError>> {
	const clockSkew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	const now = nowSeconds(options?.clock);

	const decoded = decodeEntityStatement(trustMarkJwt);
	if (!decoded.ok)
		return err(tmError(`Failed to decode trust mark JWT: ${decoded.error.description}`));

	const { header, payload } = decoded.value;

	if (header.typ !== JwtTyp.TrustMark) {
		return err(
			tmError(`Invalid typ header: expected '${JwtTyp.TrustMark}', got '${String(header.typ)}'`),
		);
	}

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

	if (options?.expectedSubject && sub !== options.expectedSubject) {
		return err(tmError("Trust mark sub does not match expected entity"));
	}

	const allowedIssuers = trustMarkIssuers[trustMarkType];
	if (allowedIssuers === undefined) {
		return err(tmError("Trust mark type not recognized"));
	}
	// Empty array = anyone may issue
	if (allowedIssuers.length > 0 && !allowedIssuers.includes(iss)) {
		return err(tmError("Issuer is not authorized for this trust mark type"));
	}

	const verifyOpts: { clockSkewSeconds: number; expectedTyp: string; clock?: Clock } = {
		clockSkewSeconds: clockSkew,
		expectedTyp: JwtTyp.TrustMark,
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
	if (exp !== undefined && exp < now - clockSkew) {
		return err(tmError(`Trust mark has expired: exp=${exp}`));
	}

	// Delegation is mandatory when the TA lists this type in trust_mark_owners
	const delegationJwt = p.delegation;
	if (options?.trustMarkOwners?.[trustMarkType] && !delegationJwt) {
		return err(
			tmError(
				`Trust mark type '${trustMarkType}' requires delegation (in trust_mark_owners) but none provided`,
			),
		);
	}

	let delegation: ValidatedTrustMarkDelegation | undefined;
	if (delegationJwt) {
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

	const validated: ValidatedTrustMark = {
		trustMarkType,
		issuer: iss,
		subject: sub,
		issuedAt: iat,
		...(exp !== undefined ? { expiresAt: exp } : {}),
		...(delegation !== undefined ? { delegation } : {}),
	};
	return ok(validated);
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

	const owners = options?.trustMarkOwners;
	if (!owners?.[trustMarkType]) {
		return err(tmError(`No trust_mark_owners configured for type '${trustMarkType}'`));
	}

	const owner = owners[trustMarkType] as TrustMarkOwner;

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
	if (dExp !== undefined && dExp < now - clockSkew) {
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

export {
	type FetchTrustMarkParams,
	type FetchTrustMarkStatusOptions,
	fetchTrustMark,
	fetchTrustMarkStatus,
	type TrustMarkStatusResult,
} from "./fetch.js";
export { type ValidateTrustMarkLogoOptions, validateTrustMarkLogo } from "./logo.js";
