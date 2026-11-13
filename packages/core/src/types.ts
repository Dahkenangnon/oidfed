/** Branded types for compile-time safety: EntityId, DiscoveryResult, and Result/Err helpers. */
import type { InternalErrorCode } from "./constants.js";
import type {
	EndpointAdditionalParameters,
	EndpointAuthenticationProvider,
	EndpointClientAuthentication,
} from "./endpoint-client.js";
import type { FederationError, Result } from "./errors.js";
import type { FederationKeyProvider } from "./federation-keys.js";
import type { DecodedFederationJwtPayload, JWKSet } from "./schemas/index.js";
import type { TrustMarkVerificationOptions } from "./trust-marks/evidence.js";
import type { TrustMarkProfile } from "./trust-marks/profiles.js";

export type { DecodedFederationJwtPayload } from "./schemas/index.js";

declare const EntityIdBrand: unique symbol;
export type EntityId = string & { readonly [EntityIdBrand]: true };

/** Parse and validate a string as an HTTPS Entity Identifier, throwing on invalid input. */
export function entityId(value: string): EntityId {
	if (value.length > 2048) throw new TypeError("Entity ID must not exceed 2048 characters");
	const url = new URL(value);
	if (url.protocol !== "https:") throw new TypeError("Entity ID must be HTTPS");
	if (url.username || url.password) throw new TypeError("Entity ID must not contain credentials");
	if (url.href.includes("?") || url.href.includes("#"))
		throw new TypeError("Entity ID must not contain query parameters or fragments");
	return value as EntityId;
}

/** Check whether a string is a valid Entity Identifier without throwing. */
export function isValidEntityId(value: string): value is EntityId {
	if (value.length > 2048) return false;
	try {
		const url = new URL(value);
		return (
			url.protocol === "https:" &&
			!url.username &&
			!url.password &&
			!url.href.includes("?") &&
			!url.href.includes("#")
		);
	} catch {
		return false;
	}
}

declare const Unverified: unique symbol;
export type ParsedEntityStatement<Payload = DecodedFederationJwtPayload> = {
	readonly header: Record<string, unknown>;
	readonly payload: Payload;
};
export type UnverifiedEntityStatement<Payload = DecodedFederationJwtPayload> =
	ParsedEntityStatement<Payload> & {
		readonly [Unverified]: true;
	};

export type HttpClient = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface Clock {
	/** Current Unix time as a NumericDate in seconds. */
	now(): number;
}

/** Returns the current time as seconds since the epoch. */
export function nowSeconds(clock?: Clock): number {
	return clock?.now() ?? Math.floor(Date.now() / 1000);
}

export interface CacheProvider {
	get<T>(key: string): Promise<T | undefined>;
	set<T>(key: string, value: T, ttlSeconds: number): Promise<void>;
	delete(key: string): Promise<void>;
	clear(): Promise<void>;
	[Symbol.asyncDispose](): Promise<void>;
}

/** Host logger. Returned promises are handled without awaiting them; sink failures are ignored. */
export interface Logger {
	debug(msg: string, context?: Record<string, unknown>): void;
	info(msg: string, context?: Record<string, unknown>): void;
	warn(msg: string, context?: Record<string, unknown>): void;
	error(msg: string, context?: Record<string, unknown>): void;
}

export interface FederationOptions {
	authentication?: EndpointClientAuthentication;
	/** Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. */
	getEndpointAuthentication?: EndpointAuthenticationProvider;
	additionalParameters?: EndpointAdditionalParameters;
	trustMarkVerification?: TrustMarkVerificationOptions;
	trustMarkIssuerKeys?: ReadonlyMap<string, JWKSet>;
	trustMarkProfiles?: readonly TrustMarkProfile[];
	/** Disallow network access when only supplied evidence is permitted. */
	offline?: boolean;
	httpClient?: HttpClient;
	/** Signed subject ECs for trust-chain validation, keyed by exact Entity Identifier. Still validated against the chain. */
	entityConfigurations?: ReadonlyMap<string, string> | undefined;
	clock?: Clock;
	cache?: CacheProvider;
	logger?: Logger;
	httpTimeoutMs?: number;
	clockSkewSeconds?: number;
	maxChainDepth?: number;
	/** Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. */
	maxChainLength?: number;
	/** Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. */
	maxResolutionSteps?: number;
	maxAuthorityHints?: number;
	maxConcurrentFetches?: number;
	maxConcurrentResolutions?: number;
	cacheMaxTtlSeconds?: number;
	signal?: AbortSignal;
	maxResponseBytes?: number;
	blockedCIDRs?: string[];
	allowedHosts?: string[];
	authorityHintFilter?: (hint: URL, subject: EntityId) => boolean;
	understoodCriticalClaims?: ReadonlySet<string>;
	/** Maximum HTTP client calls per resolution or subject-EC validation; cached and supplied statements use no allowance. Default: 50. */
	maxTotalFetches?: number;
	/**
	 * Federation-defined policy operators in addition to the seven standard ones.
	 * Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during
	 * trust-chain validation.
	 */
	customPolicyOperators?: readonly PolicyOperatorDefinition[];
	/** Federation-defined constraints checked against authenticated chains. Unknown names are ignored. */
	customConstraintChecks?: readonly ConstraintCheckDefinition[];
}

export type TrustAnchorSet = ReadonlyMap<string, Readonly<{ jwks: JWKSet }>>;

/** Create a TrustAnchorSet from a list of trust anchor configurations. */
export function createTrustAnchorSet(
	anchors: ReadonlyArray<{ readonly entityId: string; readonly jwks: JWKSet }>,
): TrustAnchorSet {
	return new Map(anchors.map((a) => [entityId(a.entityId), { jwks: a.jwks }]));
}

export interface TrustChain {
	readonly statements: ReadonlyArray<string>;
	/** ECs retrieved while resolving this candidate; pass as validation options to avoid refetching. */
	readonly entityConfigurations?: ReadonlyMap<string, string>;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata?: Readonly<Record<string, unknown>>;
}

export interface TrustChainResult {
	readonly chains: ReadonlyArray<TrustChain>;
	readonly errors: ReadonlyArray<FederationError>;
	/** Resolution stopped before examining its configured scope because of a limit or cancellation. */
	readonly incomplete?: true;
}

export interface ValidatedTrustChain {
	readonly statements: ReadonlyArray<ParsedEntityStatement>;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata: Readonly<Record<string, Record<string, unknown>>>;
	readonly trustMarks: ReadonlyArray<ValidatedTrustMark>;
	/** Evaluation of each published subject mark, in reference order. */
	readonly trustMarkEvaluations: ReadonlyArray<TrustMarkEvaluation>;
}

export type ValidationResult =
	| {
			readonly valid: true;
			readonly chain: ValidatedTrustChain;
			readonly errors: ReadonlyArray<ValidationError>;
	  }
	| {
			readonly valid: false;
			readonly chain?: undefined;
			readonly errors: ReadonlyArray<ValidationError>;
	  };

export interface ValidationError {
	readonly code: InternalErrorCode;
	readonly message: string;
	readonly statementIndex?: number;
	readonly field?: string;
	readonly checkNumber?: number;
}

/** Evaluation of a Trust Mark, independent of the enclosing chain's validity. */
export type TrustMarkEvaluation = Readonly<{
	referenceIndex: number;
	trustMarkType: string;
}> &
	(
		| Readonly<{ status: "verified"; mark: ValidatedTrustMark }>
		| Readonly<{ status: "invalid"; error: FederationError }>
		| Readonly<{
				status: "unevaluated";
				reason: "not_evaluated" | "issuer_policy_unavailable" | "issuer_keys_unavailable";
				description: string;
		  }>
	);

export interface TrustMarkEvidence extends ValidatedTrustMark {
	readonly jwt: string;
	readonly claims: Readonly<Record<string, unknown>>;
	readonly verificationKey: Readonly<{
		source: "current" | "historical";
		kid: string;
		responseJwt?: string;
	}>;
}

export interface ValidatedTrustMark {
	/** Authenticated issuer context retained for subsequent status checks; federation provenance is runtime-bound. */
	readonly issuerEvidence?: import("./trust-marks/evidence.js").TrustMarkIssuerContext;
	/** Present on marks validated by current core APIs; optional for older host-created records. */
	readonly jwt?: string;
	readonly claims?: Readonly<Record<string, unknown>>;
	/** Expiry of the evidence supporting this assessment; distinct from the token expiry. */
	readonly verificationExpiresAt?: number;
	readonly trustMarkType: string;
	readonly issuer: string;
	readonly subject: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
	readonly delegation?: Readonly<ValidatedTrustMarkDelegation>;
}

export interface ValidatedTrustMarkDelegation {
	readonly issuer: string;
	readonly subject: string;
	readonly trustMarkType: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
}

type ConstraintReadonly<T> = T extends object
	? { readonly [K in keyof T]: ConstraintReadonly<T[K]> }
	: T;

/** Detached, recursively frozen evidence. Position uses leaf-first chain indexing. */
export interface ConstraintCheckContext {
	readonly issuerId: EntityId;
	readonly subjectId: EntityId;
	readonly trustChainSubjectId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly position: number;
	readonly statements: ConstraintReadonly<readonly ParsedEntityStatement[]>;
}

/** Synchronous checks may run again when prepared validation is completed. */
export interface ConstraintCheckDefinition {
	readonly name: string;
	check(value: unknown, context: ConstraintCheckContext): Result<void, FederationError>;
}

export interface PolicyOperatorDefinition {
	name: string;
	order: number;
	action: "check" | "modify" | "both";
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult;
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult;
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean;
}

export type PolicyOperatorResult =
	| { ok: true; value: unknown; removed?: boolean }
	| { ok: false; error: string };

export type PolicyMergeResult = { ok: true; value: unknown } | { ok: false; error: string };

export type ResolvedMetadataPolicy = Record<string, Record<string, Record<string, unknown>>>;

export type ChainSelectionStrategy = (chains: ValidatedTrustChain[]) => ValidatedTrustChain;

declare const _discoveryBrand: unique symbol;

/**
 * Result of entity discovery through the federation.
 *
 * Branded to prevent callers from constructing unchecked inputs —
 * only `discoverEntity()` (in `@oidfed/leaf`) produces this type.
 */
export type DiscoveryResult = {
	readonly [_discoveryBrand]: true;
	readonly entityId: EntityId;
	readonly resolvedMetadata: Readonly<Record<string, Record<string, unknown>>>;
	readonly trustChain: ValidatedTrustChain;
	readonly trustMarks: ReadonlyArray<ValidatedTrustMark>;
};

export interface EntityContext {
	readonly entityId: string;
	readonly keyProvider: FederationKeyProvider;
	readonly options?: FederationOptions | undefined;
	readonly trustAnchors?: TrustAnchorSet;
	readonly authorityHints?: readonly EntityId[];
}

export interface EntityRole {
	readonly type: string;
	readonly metadata: Record<string, unknown>;
	readonly routes?: ReadonlyMap<string, (request: Request) => Promise<Response>>;
	initialize?(context: EntityContext): void;
	/** Validate the final composed role block before its host publishes metadata. */
	validateMetadata?(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
}
