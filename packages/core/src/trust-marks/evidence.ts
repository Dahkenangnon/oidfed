import { freezeSnapshot } from "../callbacks.js";
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	FederationErrorCode,
	InternalErrorCode,
} from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import {
	selectHistoricalVerificationKey,
	verifyHistoricalKeysResponse,
} from "../federation-api/index.js";
import { decodeEntityConfiguration, decodeEntityStatement } from "../jose/verify.js";
import { type JWKSet, JWKSetSchema } from "../schemas/jwk.js";
import {
	type FederationEntityMetadata,
	FederationEntityMetadataSchema,
} from "../schemas/metadata.js";
import { type TrustMarkOwner, TrustMarkOwnerSchema } from "../schemas/trust-mark.js";
import { resolveTrustChains } from "../trust-chain/resolve.js";
import { selectTrustChain } from "../trust-chain/selection.js";
import { validateTrustChainStructure } from "../trust-chain/validate.js";
import type { ValidatedTrustChain } from "../types.js";
import {
	entityId,
	type FederationOptions,
	nowSeconds,
	type TrustAnchorSet,
	type TrustMarkEvidence,
} from "../types.js";
import { type TrustMarkValidationOptions, validateTrustMark } from "./index.js";
import { fetchTrustMarkHistoricalResponse, trustMarkOperation } from "./operation.js";

export interface FederationTrustMarkIssuerEvidence {
	readonly kind: "federation";
	readonly issuer: string;
	readonly trustMarkType: string;
	readonly trustAnchorId: string;
	readonly statements: readonly string[];
	readonly entityConfigurations: Readonly<Record<string, string>>;
	readonly keys: JWKSet;
	readonly expiresAt: number;
	readonly metadata?: FederationEntityMetadata;
	readonly trustMarkIssuers: Readonly<Record<string, readonly string[]>>;
	readonly trustMarkOwners: Readonly<Record<string, TrustMarkOwner>>;
}
export interface OutOfBandTrustMarkIssuer {
	readonly kind: "out-of-band";
	readonly issuer: string;
	readonly allowedTrustMarkTypes: readonly string[];
	readonly keys: JWKSet;
	readonly trustMarkOwners?: Readonly<Record<string, TrustMarkOwner>>;
	/** Independently trusted endpoint metadata, never taken from the submitted token. */
	readonly metadata?: FederationEntityMetadata;
}
export type TrustMarkIssuerContext = FederationTrustMarkIssuerEvidence | OutOfBandTrustMarkIssuer;
export interface HistoricalTrustMarkOptions {
	readonly mode: "on-missing-kid" | "supplied-only";
	readonly responses?: readonly string[];
	readonly maxAgeSeconds: number;
	readonly allowedRevocationReasons?: readonly string[];
	readonly securityRevocationReasons?: readonly string[];
}
export interface TrustMarkVerificationOptions {
	readonly mode?: "provided" | "resolve";
	readonly issuerEvidence?: readonly TrustMarkIssuerContext[];
	readonly trustAnchors?: TrustAnchorSet;
	readonly historicalKeys?: HistoricalTrustMarkOptions;
}
export interface EstablishTrustMarkIssuerOptions {
	readonly issuer: string;
	readonly trustMarkType: string;
	readonly trustAnchors: TrustAnchorSet;
	readonly trustChain?: readonly string[];
	readonly entityConfigurations?: ReadonlyMap<string, string>;
	readonly options?: FederationOptions;
}
const issuedEvidence = new WeakSet<object>();
function failure(description: string) {
	return err({ code: InternalErrorCode.TrustMarkInvalid, description });
}
function unavailableIssuer() {
	return err({
		code: FederationErrorCode.TemporarilyUnavailable,
		description: "Issuer discovery was incomplete",
	});
}

/** Validate supplied proofs or discover an eligible issuer chain without recursive mark evaluation. */
export async function establishTrustMarkIssuerTrust(
	input: EstablishTrustMarkIssuerOptions,
): Promise<Result<FederationTrustMarkIssuerEvidence>> {
	try {
		entityId(input.issuer);
		if (!input.trustMarkType) return failure("A Trust Mark type is required");
		// A subject's registration request is not evidence about its accreditation issuer.
		const {
			explicitRegistrationAudience: _audience,
			explicitRegistrationRequest: _request,
			entityConfigurationJwt: _configuration,
			...issuerOptions
		} = (input.options ?? {}) as FederationOptions & {
			explicitRegistrationAudience?: unknown;
			explicitRegistrationRequest?: unknown;
			entityConfigurationJwt?: unknown;
		};
		const options = trustMarkOperation({
			...issuerOptions,
			...(input.entityConfigurations ? { entityConfigurations: input.entityConfigurations } : {}),
		});
		if (options.signal?.aborted) return failure("Operation cancelled");
		let candidates: readonly {
			statements: readonly string[];
			entityConfigurations?: ReadonlyMap<string, string>;
		}[];
		let discoveryUnavailable = false;
		if (input.trustChain)
			candidates = [
				{
					statements: input.trustChain,
					...(input.entityConfigurations
						? { entityConfigurations: input.entityConfigurations }
						: {}),
				},
			];
		else {
			if (options.offline) return failure("Offline issuer validation requires a supplied chain");
			const resolved = await resolveTrustChains(
				entityId(input.issuer),
				input.trustAnchors,
				options,
			);
			if (resolved.incomplete) return unavailableIssuer();
			discoveryUnavailable = resolved.errors.some(
				(error) =>
					error.code === InternalErrorCode.Network || error.code === InternalErrorCode.Timeout,
			);
			candidates = resolved.chains;
		}
		const eligible: { chain: ValidatedTrustChain; evidence: FederationTrustMarkIssuerEvidence }[] =
			[];
		for (const candidate of [...candidates].sort(
			(a, b) => a.statements.length - b.statements.length,
		)) {
			const checked = await validateTrustChainStructure(candidate.statements, input.trustAnchors, {
				...options,
				...(candidate.entityConfigurations
					? { entityConfigurations: candidate.entityConfigurations }
					: {}),
			});
			if (!checked.valid || checked.chain.entityId !== input.issuer) continue;
			const ec = decodeEntityConfiguration(candidate.statements[0] ?? "");
			const root = checked.chain.statements.at(-1)?.payload;
			if (!ec.ok || !root || root.iss !== root.sub) continue;
			const issuers = root.trust_mark_issuers;
			if (!issuers || !Object.hasOwn(issuers, input.trustMarkType)) continue;
			const allowed = issuers[input.trustMarkType];
			if (
				!Array.isArray(allowed) ||
				(allowed.length && !allowed.some((issuer) => issuer === input.issuer))
			)
				continue;
			const rawMetadata = ec.value.payload.metadata?.federation_entity;
			const metadata =
				rawMetadata === undefined ? undefined : FederationEntityMetadataSchema.parse(rawMetadata);
			const evidence: FederationTrustMarkIssuerEvidence = freezeSnapshot(
				structuredClone({
					kind: "federation",
					issuer: input.issuer,
					trustMarkType: input.trustMarkType,
					trustAnchorId: checked.chain.trustAnchorId,
					statements: [...candidate.statements],
					entityConfigurations: Object.fromEntries(
						candidate.entityConfigurations ?? options.entityConfigurations ?? [],
					),
					keys: ec.value.payload.jwks,
					expiresAt: checked.chain.expiresAt,
					trustMarkIssuers: issuers,
					trustMarkOwners: root.trust_mark_owners ?? {},
					...(metadata ? { metadata } : {}),
				}),
			);
			if (options.signal?.aborted) return failure("Operation cancelled");
			if (!options.chainSelection) {
				issuedEvidence.add(evidence);
				return ok(evidence);
			}
			eligible.push({ chain: checked.chain, evidence });
		}
		if (eligible.length) {
			const selected = selectTrustChain(
				eligible.map((item) => item.chain),
				options,
			);
			if (!selected.ok) return selected;
			const evidence = eligible.find((item) => item.chain === selected.value)?.evidence;
			if (!evidence) return failure("Selected issuer evidence is unavailable");
			issuedEvidence.add(evidence);
			return ok(evidence);
		}
		return discoveryUnavailable
			? unavailableIssuer()
			: failure("No valid issuer chain authorizes this Trust Mark type");
	} catch {
		return failure("Unable to establish Trust Mark issuer trust");
	}
}

/** Check evidence each time it is used; plain JSON cannot impersonate a validated issuer chain. */
export function trustMarkIssuerContext(
	context: TrustMarkIssuerContext,
	type: string,
	options?: FederationOptions,
): Result<{
	issuer: string;
	keys: JWKSet;
	owners: Record<string, TrustMarkOwner>;
	metadata?: FederationEntityMetadata;
	expiresAt?: number;
}> {
	try {
		if (options?.signal?.aborted) return failure("Operation cancelled");
		entityId(context.issuer);
		if (context.kind === "federation") {
			if (
				!issuedEvidence.has(context) ||
				context.trustMarkType !== type ||
				context.expiresAt <= nowSeconds(options?.clock)
			)
				return failure("Unknown, expired, or inapplicable issuer evidence");
		} else if (
			context.kind !== "out-of-band" ||
			!Array.isArray(context.allowedTrustMarkTypes) ||
			!context.allowedTrustMarkTypes.includes(type)
		)
			return failure("Issuer context does not authorize this Trust Mark type");
		const owners = structuredClone(context.trustMarkOwners ?? {});
		for (const owner of Object.values(owners)) TrustMarkOwnerSchema.parse(owner);
		return ok({
			issuer: context.issuer,
			keys: JWKSetSchema.parse(structuredClone(context.keys)),
			owners,
			...(context.metadata
				? { metadata: FederationEntityMetadataSchema.parse(structuredClone(context.metadata)) }
				: {}),
			...(context.kind === "federation" ? { expiresAt: context.expiresAt } : {}),
		});
	} catch {
		return failure("Invalid Trust Mark issuer context");
	}
}

export interface ValidateTrustMarkWithIssuerOptions extends TrustMarkValidationOptions {
	readonly expectedTrustMarkType: string;
	readonly historicalKeys?: HistoricalTrustMarkOptions;
}
export async function validateTrustMarkWithIssuer(
	jwt: string,
	context: TrustMarkIssuerContext,
	input: ValidateTrustMarkWithIssuerOptions,
): Promise<Result<TrustMarkEvidence>> {
	try {
		const options = trustMarkOperation(input);
		const trusted = trustMarkIssuerContext(context, options.expectedTrustMarkType, options);
		if (!trusted.ok) return trusted;
		const decoded = decodeEntityStatement(jwt);
		if (!decoded.ok) return decoded;
		if (decoded.value.payload.iss !== trusted.value.issuer)
			return failure("Trust Mark issuer does not match trusted context");
		let keys = trusted.value.keys;
		let responseJwt: string | undefined;
		let historyDeadline = Infinity;
		const kid = decoded.value.header.kid;
		const history = options.historicalKeys;
		if (typeof kid !== "string" || !kid) return failure("Trust Mark must contain a kid");
		if (!keys.keys.some((key) => key.kid === kid) && history) {
			if (!Number.isFinite(history.maxAgeSeconds) || history.maxAgeSeconds <= 0)
				return failure("Historical response maxAgeSeconds must be finite and positive");
			if (history.mode !== "on-missing-kid" && history.mode !== "supplied-only")
				return failure("Unknown historical key resolution mode");
			const responses = [...(history.responses ?? [])];
			if (!responses.length && history.mode === "on-missing-kid" && !options.offline) {
				const endpoint = trusted.value.metadata?.federation_historical_keys_endpoint;
				if (!endpoint) return failure("Issuer does not publish historical keys");
				const fetched = await fetchTrustMarkHistoricalResponse(
					endpoint,
					trusted.value.issuer,
					options,
				);
				if (!fetched.ok) return fetched;
				responses.push(fetched.value);
			}
			const candidates = [];
			for (const response of responses) {
				const verified = await verifyHistoricalKeysResponse(response, trusted.value.keys, {
					...options,
					expectedIssuer: trusted.value.issuer,
				});
				if (!verified.ok) return verified;
				const now = nowSeconds(options.clock),
					skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
				if (verified.value.iat > now + skew || now >= verified.value.iat + history.maxAgeSeconds)
					return failure("Historical response is stale or issued in the future");
				if (!verified.value.keys.some((key) => key.kid === kid)) continue;
				const selected = selectHistoricalVerificationKey(verified.value.keys, {
					kid,
					validAt: decoded.value.payload.iat,
					...(history.allowedRevocationReasons
						? { allowedRevocationReasons: history.allowedRevocationReasons }
						: {}),
					...(history.securityRevocationReasons
						? { securityRevocationReasons: history.securityRevocationReasons }
						: {}),
				});
				if (!selected.ok) return selected;
				candidates.push({
					key: selected.value,
					response,
					deadline: verified.value.iat + history.maxAgeSeconds,
				});
			}
			if (candidates.length !== 1)
				return failure("Historical signing key is unavailable or ambiguous");
			const selected = candidates[0];
			if (!selected) return failure("Historical signing key is unavailable");
			keys = { keys: [selected.key] };
			responseJwt = selected.response;
			historyDeadline = selected.deadline;
		}
		const verified = await validateTrustMark(
			jwt,
			{ [options.expectedTrustMarkType]: [trusted.value.issuer] },
			keys,
			{ ...options, trustMarkOwners: trusted.value.owners },
		);
		if (!verified.ok) return verified;
		const deadline = Math.min(
			verified.value.verificationExpiresAt ?? Infinity,
			trusted.value.expiresAt ?? Infinity,
			historyDeadline,
		);
		if (deadline <= nowSeconds(options.clock) || options.signal?.aborted)
			return failure("Trust Mark verification evidence expired or was cancelled");
		return ok(
			freezeSnapshot({
				...verified.value,
				issuerEvidence:
					context.kind === "federation" ? context : freezeSnapshot(structuredClone(context)),
				...(Number.isFinite(deadline) ? { verificationExpiresAt: deadline } : {}),
				verificationKey: responseJwt
					? { source: "historical" as const, kid, responseJwt }
					: { source: "current" as const, kid },
			}),
		);
	} catch {
		return failure("Trust Mark verification failed");
	}
}
