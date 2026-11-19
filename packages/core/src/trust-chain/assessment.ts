import { cloneData } from "../data-copy.js";
/** Entity assessments from local chain validation or an explicitly trusted resolver. */

import { freezeSnapshot } from "../callbacks.js";
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_MAX_CHAIN_DEPTH,
	DEFAULT_MAX_CHAIN_LENGTH,
	InternalErrorCode,
	MediaType,
} from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { RESOLVE_UNORDERED_PARAMETERS } from "../endpoint-parameters.js";
import { err, ok, type Result } from "../errors.js";
import { verifyResolveResponse } from "../federation-api/index.js";
import {
	decodeEntityConfiguration,
	decodeEntityStatement,
	decodeSubordinateStatement,
} from "../jose/verify.js";
import type { ResolveResponsePayload } from "../schemas/entity-statement.js";
import { type JWKSet, JWKSetSchema } from "../schemas/jwk.js";
import { TrustMarkDelegationPayloadSchema, TrustMarkPayloadSchema } from "../schemas/trust-mark.js";
import {
	type DiscoveryResult,
	type EntityId,
	entityId,
	type FederationOptions,
	nowSeconds,
	type TrustAnchorSet,
	type TrustChainResult,
	type ValidationError,
} from "../types.js";
import { discoverEntity, discoverEntityFromChain } from "./discovery.js";
import { createTrustChainOperation } from "./operation.js";
import { validateResolvedMetadata } from "./validate.js";

export interface TrustedResolverConfig {
	readonly entityId: EntityId | string;
	readonly endpoint: string;
	/** Explicit authorization of this resolver, separately from the subject's anchors. */
	readonly trust:
		| { readonly kind: "pinned"; readonly jwks: JWKSet }
		| { readonly kind: "federation"; readonly trustAnchors: TrustAnchorSet };
	/** Recipient identity for custom endpoint authentication; private_key_jwt infers its clientId. */
	readonly requester?: EntityId | string;
}
export type TrustResolutionSource =
	| { readonly kind: "bottom-up" }
	| { readonly kind: "resolver"; readonly resolver: TrustedResolverConfig };
export interface EntityAssessmentOptions extends FederationOptions {
	/** Delegation is explicit. The default locally validates the subject chain. */
	mode?: "local" | "resolver";
	/** Explicit subject evidence for local assessment, including offline use. */
	trustChain?: readonly string[];
}
export type EntityAssessment =
	| {
			readonly kind: "local";
			readonly entityId: EntityId;
			readonly expiresAt: number;
			readonly discovery: DiscoveryResult;
			readonly resolvedMetadata: DiscoveryResult["resolvedMetadata"];
	  }
	| {
			readonly kind: "resolver";
			readonly entityId: EntityId;
			readonly resolver: EntityId;
			readonly trustAnchorId: EntityId;
			readonly expiresAt: number;
			readonly responseJwt: string;
			readonly statements: readonly string[];
			readonly resolvedMetadata: ResolveResponsePayload["metadata"];
			readonly reportedTrustMarks: NonNullable<ResolveResponsePayload["trust_marks"]>;
	  };

const assessments = new WeakSet<object>();
/** Recognize process-local assessment evidence; copied or deserialized objects are not accepted. */
export function isEntityAssessment(value: unknown): value is EntityAssessment {
	return typeof value === "object" && value !== null && assessments.has(value);
}
function failure(description: string): Result<never> {
	return err({ code: InternalErrorCode.TrustChainInvalid, description });
}

/** Authenticate the assessment without representing its subject chain as locally verified. */
async function resolverAssessment(
	subject: EntityId,
	anchors: TrustAnchorSet,
	options: FederationOptions,
): Promise<Result<Extract<EntityAssessment, { kind: "resolver" }>>> {
	try {
		const operation = createTrustChainOperation(options);
		if (!operation.ok) return operation;
		options = operation.value.options;
		const source = options.trustResolution;
		if (source?.kind !== "resolver") return failure("A trusted resolver must be configured");
		if (options.offline || options.signal?.aborted)
			return failure("Resolver access is unavailable offline or after cancellation");
		if (!anchors.size) return failure("Subject trust anchors are required");
		const resolver = source.resolver;
		const issuer = entityId(resolver.entityId);
		entityId(subject);
		const localOptions: FederationOptions = { ...options, trustResolution: { kind: "bottom-up" } };
		delete localOptions.chainSelection;
		let keys: JWKSet;
		let deadline = Infinity;
		if (resolver.trust.kind === "pinned") keys = JWKSetSchema.parse(resolver.trust.jwks);
		else {
			const proof = await discoverEntity(issuer, resolver.trust.trustAnchors, localOptions);
			if (!proof.ok) return proof;
			keys = JWKSetSchema.parse(proof.value.trustChain.statements[0]?.payload.jwks);
			deadline = proof.value.trustChain.expiresAt;
		}
		let requester = resolver.requester;
		const capture = (auth: FederationOptions["authentication"]) => {
			if (auth && "clientId" in auth) {
				if (requester !== undefined && requester !== auth.clientId)
					throw new Error("Conflicting requester identity");
				requester = auth.clientId;
			}
			return auth;
		};
		const selectors = new URLSearchParams({ sub: subject });
		for (const anchor of anchors.keys()) selectors.append("trust_anchor", entityId(anchor));
		const authentication = capture(options.authentication);
		const provider = options.getEndpointAuthentication;
		const response = await fetchFederationEndpoint(
			resolver.endpoint,
			selectors,
			{
				...options,
				...(authentication ? { authentication } : {}),
				...(provider
					? {
							getEndpointAuthentication: async (context) => capture(await provider(context)),
						}
					: {}),
				method: "GET",
				expectedStatus: 200,
				federationErrors: true,
				accept: MediaType.ResolveResponse,
				expectedContentType: MediaType.ResolveResponse,
			},
			issuer,
			RESOLVE_UNORDERED_PARAMETERS,
		);
		if (!response.ok) return response;
		const verified = await verifyResolveResponse(response.value, keys, {
			...options,
			expectedIssuer: issuer,
			expectedSubject: subject,
			...(requester ? { expectedAudience: entityId(requester) } : {}),
			...(options.clock ? { clock: options.clock } : {}),
			...(options.clockSkewSeconds !== undefined
				? { clockSkewSeconds: options.clockSkewSeconds }
				: {}),
		});
		if (!verified.ok) return verified;
		const payload = verified.value;
		const metadataErrors: ValidationError[] = [];
		validateResolvedMetadata(
			metadataErrors,
			payload.metadata as Record<string, Record<string, unknown>>,
			subject,
			undefined,
			options.algorithmRegistry,
		);
		if (metadataErrors.length)
			return failure(metadataErrors.map((error) => error.message).join("; "));
		const now = nowSeconds(options.clock);
		if (
			payload.iat > now + (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) ||
			payload.exp <= payload.iat
		)
			return failure("Invalid Resolve Response validity interval");
		const raw = payload.trust_chain;
		if (
			!raw.length ||
			raw.length > (options.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH) ||
			raw.length > (options.maxChainDepth ?? DEFAULT_MAX_CHAIN_DEPTH) + 2
		)
			return failure("Invalid Resolve Response chain length");
		const statements = [];
		for (const jwt of raw) {
			const decoded = decodeEntityStatement(jwt, options);
			if (!decoded.ok) return failure("Invalid Resolve Response subject chain");
			const shaped =
				decoded.value.payload.iss === decoded.value.payload.sub
					? decodeEntityConfiguration(jwt, options)
					: decodeSubordinateStatement(jwt, options);
			if (!shaped.ok) return failure("Invalid Resolve Response Entity Statement shape");
			statements.push(shaped.value.payload);
		}
		const leaf = decodeEntityConfiguration(raw[0] ?? "", options);
		if (
			!leaf.ok ||
			String(leaf.value.payload.iss) !== subject ||
			String(leaf.value.payload.sub) !== subject
		)
			return failure("Resolve Response chain subject mismatch");
		const visited = new Set<string>([subject]);
		for (let i = 1; i < statements.length; i++) {
			const statement = statements[i];
			const previous = statements[i - 1];
			if (!statement || !previous) return failure("Missing Resolve Response statement");
			const expected = i === 1 ? subject : previous.iss;
			if (
				statement.sub !== expected ||
				(statement.iss === statement.sub && (i === 1 || i !== statements.length - 1))
			)
				return failure("Invalid Resolve Response chain links");
			if (statement.iss !== statement.sub) {
				if (visited.has(statement.iss)) return failure("Resolve Response chain contains a loop");
				visited.add(statement.iss);
			}
		}
		const anchor = entityId(statements.at(-1)?.iss ?? "");
		if (!anchors.has(anchor)) return failure("Resolve Response uses an unrequested Trust Anchor");
		deadline = Math.min(deadline, payload.exp, ...statements.map((statement) => statement.exp));
		for (const ref of payload.trust_marks ?? []) {
			const mark = decodeEntityStatement(ref.trust_mark, options);
			if (!mark.ok) return failure("Malformed reported Trust Mark");
			const shape = TrustMarkPayloadSchema.safeParse(mark.value.payload);
			if (!shape.success) return failure("Malformed reported Trust Mark claims");
			const claims = shape.data;
			if (String(claims.sub) !== subject || claims.trust_mark_type !== ref.trust_mark_type)
				return failure("Reported Trust Mark identity mismatch");
			if (claims.exp !== undefined) {
				if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp))
					return failure("Invalid reported Trust Mark expiry");
				deadline = Math.min(deadline, claims.exp);
			}
			if (claims.delegation !== undefined) {
				if (typeof claims.delegation !== "string") return failure("Invalid reported delegation");
				const delegation = decodeEntityStatement(claims.delegation, options);
				if (!delegation.ok) return failure("Invalid reported delegation");
				const delegated = TrustMarkDelegationPayloadSchema.safeParse(delegation.value.payload);
				if (
					!delegated.success ||
					delegated.data.sub !== claims.iss ||
					delegated.data.trust_mark_type !== claims.trust_mark_type
				)
					return failure("Malformed reported delegation claims");
				const exp = delegated.data.exp;
				if (exp !== undefined) deadline = Math.min(deadline, exp);
			}
		}
		if (operation.value.exhausted())
			return failure("Resolver assessment exhausted its resource limits");
		if (
			!Number.isFinite(deadline) ||
			deadline <= nowSeconds(options.clock) ||
			options.signal?.aborted
		)
			return failure("Resolver assessment has expired or was cancelled");
		const assessment = freezeSnapshot({
			kind: "resolver" as const,
			entityId: subject,
			resolver: issuer,
			trustAnchorId: anchor,
			expiresAt: deadline,
			responseJwt: response.value,
			statements: [...raw],
			resolvedMetadata: cloneData(payload.metadata),
			reportedTrustMarks: cloneData(payload.trust_marks ?? []),
		});
		assessments.add(assessment);
		return ok(assessment);
	} catch {
		return failure("Unable to authenticate resolver assessment");
	}
}

/** Acquire candidate evidence for the caller to validate as a subject chain. */
export async function resolveThroughTrustedResolver(
	subject: EntityId,
	anchors: TrustAnchorSet,
	options: FederationOptions,
): Promise<TrustChainResult> {
	const result = await resolverAssessment(subject, anchors, options);
	if (!result.ok) return { chains: [], errors: [result.error] };
	return {
		chains: [
			{
				entityId: subject,
				trustAnchorId: result.value.trustAnchorId,
				expiresAt: result.value.expiresAt,
				statements: result.value.statements,
				...(options.entityConfigurations
					? { entityConfigurations: options.entityConfigurations }
					: {}),
			},
		],
		errors: [],
	};
}

/**
 * Assess an entity through local chain validation or an explicitly authorized resolver.
 * Resolver authorization is configured separately from trust in the assessed entity.
 */
export async function assessEntity(
	subject: EntityId,
	anchors: TrustAnchorSet,
	options: EntityAssessmentOptions,
): Promise<Result<EntityAssessment>> {
	if (options.mode === "resolver") {
		if (
			options.trustChain ||
			options.chainSelection ||
			options.customConstraintChecks?.length ||
			options.customPolicyOperators?.length
		)
			return failure("Local selection and policy callbacks require local assessment mode");
		return resolverAssessment(subject, anchors, options);
	}
	const discovery = options.trustChain
		? await discoverEntityFromChain(subject, options.trustChain, anchors, options)
		: await discoverEntity(subject, anchors, options);
	if (!discovery.ok) return discovery;
	const assessment = freezeSnapshot({
		kind: "local" as const,
		entityId: subject,
		expiresAt: discovery.value.trustChain.expiresAt,
		discovery: discovery.value,
		resolvedMetadata: discovery.value.resolvedMetadata,
	});
	assessments.add(assessment);
	return ok(assessment);
}
