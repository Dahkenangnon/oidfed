/** Shared federation identifiers, trust evidence, options, and extension contracts. */

import type { CryptoEngine, FederationArtifact, Keyring } from "@oidfed/crypto";
import type { InternalErrorCode } from "./constants.js";
import type {
	EndpointAdditionalParameters,
	EndpointAuthenticationProvider,
	EndpointClientAuthentication,
} from "./endpoint-client.js";
import type { FederationError, Result } from "./errors.js";
import type { DecodedFederationJwtPayload, JWKSet } from "./schemas/index.js";
import type { TrustMarkVerificationOptions } from "./trust-marks/evidence.js";
import type { TrustMarkProfile } from "./trust-marks/profiles.js";

export type { DecodedFederationJwtPayload } from "./schemas/index.js";

declare const EntityIdBrand: unique symbol;
export type EntityId = string & { readonly [EntityIdBrand]: true };

function entityIdError(value: string): string | undefined {
	if (typeof value !== "string") return "Entity ID must be a string";
	if (value.length > 2048) return "Entity ID must not exceed 2048 characters";
	if (/\s/u.test(value) || value.includes("\\"))
		return "Entity ID must not contain raw whitespace or backslashes";
	for (const character of value) {
		const code = character.charCodeAt(0);
		if (
			code < 0x20 ||
			(code >= 0x7f && code <= 0x9f) ||
			(character.length === 1 && code >= 0xd800 && code <= 0xdfff)
		)
			return "Entity ID must not contain control characters or unpaired surrogates";
	}
	const authority = /^https:\/\/([^/?#]+)/i.exec(value)?.[1];
	if (!authority) return "Entity ID must be an HTTPS URL with a host";
	if (authority.includes("@")) return "Entity ID must not contain credentials";
	if (value.includes("?") || value.includes("#"))
		return "Entity ID must not contain query parameters or fragments";
	if (!URL.canParse(value)) return "Entity ID must be a valid HTTPS URL";
	return undefined;
}

/** Validate an HTTPS Entity Identifier and return the original string. */
export function entityId(value: string): EntityId {
	const error = entityIdError(value);
	if (error) throw new TypeError(error);
	return value as EntityId;
}

/** Check whether a string is a valid Entity Identifier without throwing or rewriting it. */
export function isValidEntityId(value: string): value is EntityId {
	return entityIdError(value) === undefined;
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

/** A host clock returned a value that cannot be used as a JWT NumericDate. */
export class InvalidClockError extends RangeError {
	readonly code = "ERR_INVALID_CLOCK" as const;
	constructor() {
		super("Clock must return finite Unix seconds");
		this.name = "InvalidClockError";
	}
}
/** Return finite Unix seconds. Invalid host clocks throw before any deadline comparison. */
export function nowSeconds(clock?: Clock): number {
	const now = clock ? clock.now() : Math.floor(Date.now() / 1000);
	if (typeof now !== "number" || !Number.isFinite(now)) throw new InvalidClockError();
	return now;
}

/** Host logger. Returned promises are handled without awaiting them; sink failures are ignored. */
export interface Logger {
	debug(msg: string, context?: Record<string, unknown>): void;
	info(msg: string, context?: Record<string, unknown>): void;
	warn(msg: string, context?: Record<string, unknown>): void;
	error(msg: string, context?: Record<string, unknown>): void;
}

/** Dependencies shared by signing hosts; private custody stays inside the keyring. */
export interface CryptoContext {
	/** Public cryptographic operations owned by the application. */
	readonly engine: CryptoEngine;
	/** Atomic public-key snapshots and stable private signing bindings. */
	readonly keyring: Keyring;
	/** Immutable public key and algorithm definitions for this host and its roles. */
	readonly algorithmRegistry?: import("@oidfed/crypto").JwsAlgorithmRegistry | undefined;
	/** Local purpose for Federation Entity Keys. Defaults to federation. */
	readonly federationPurpose?: import("@oidfed/crypto").KeyPurpose;
	/** Trusted Federation JWKS from the issuer's current publication, when managed separately. */
	readonly readPublishedFederationJwks?: (issuer: EntityId) => JWKSet | Promise<JWKSet>;
	/** Required when historical-key features are configured. */
	readonly history?: import("./federation-keys.js").FederationKeyHistorySource;
}
/** Per-operation policy on a host whose engine is already bound. */
export type BoundFederationOptions<Options extends FederationOptions = FederationOptions> = Omit<
	Options,
	"engine" | "algorithmRegistry" | "storage"
>;

export interface FederationOptions {
	/** Explicit cryptographic backend. No global backend is selected by the library. */
	readonly engine: CryptoEngine;
	/** Definitions used by standalone operations; bound hosts supply their own registry. */
	readonly algorithmRegistry?: import("@oidfed/crypto").JwsAlgorithmRegistry | undefined;
	/** Algorithms permitted for signing and verification with Federation Entity Keys. */
	readonly allowedFederationAlgorithms?: readonly string[] | undefined;
	/** Further restrict the Federation allowlist for the given operation. An empty list denies it. */
	readonly allowedAlgorithmsForArtifact?:
		| ((artifact: FederationArtifact) => readonly string[])
		| undefined;
	/** Local algorithm policy for protocol-key operations. */
	readonly allowedAlgorithms?: readonly string[];
	/** Maximum matching keys tried for one JWT. Defaults to 16. */
	readonly maxVerificationCandidates?: number;
	/** Maximum encoded compact JWT bytes. Defaults to the crypto package limit. */
	readonly maxCompactBytes?: number | undefined;
	/** How to acquire evidence. Protocol consumers validate the returned subject chain. */
	trustResolution?: import("./trust-chain/assessment.js").TrustResolutionSource;
	/** Select among validated candidates eligible for the current operation. */
	chainSelection?: ChainSelectionStrategy;
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
	/** Signed subject ECs keyed by exact Entity Identifier. Each is validated against the chain. */
	entityConfigurations?: ReadonlyMap<string, string> | undefined;
	clock?: Clock;
	/** Optional storage supplied by the standalone caller or bound by its host. */
	readonly storage?: import("./storage/contracts.js").FederationStorage | undefined;
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
	/** Fetched statement cache retention cap in seconds. Defaults to 3600, bounded by the statement's exp. */
	cacheMaxTtlSeconds?: number;
	signal?: AbortSignal;
	maxResponseBytes?: number;
	blockedCIDRs?: string[];
	allowedHosts?: string[];
	authorityHintFilter?: (hint: URL, subject: EntityId) => boolean;
	understoodCriticalClaims?: ReadonlySet<string>;
	/** Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. */
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
 * Discovery evidence produced by `discoverEntity()` or `discoverEntityFromChain()` in core.
 * The brand distinguishes validated discovery results from unchecked input.
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
	readonly crypto: CryptoContext;
	readonly storage?: import("./storage/contracts.js").FederationStorage;
	readonly options: FederationOptions;
	readonly trustAnchors?: TrustAnchorSet;
	readonly authorityHints?: readonly EntityId[];
}

export interface EntityRole {
	readonly type: string;
	readonly metadata: Record<string, unknown>;
	readonly routes?: ReadonlyMap<string, (request: Request) => Promise<Response>>;
	initialize?(context: EntityContext): void | Promise<void>;
	/** Rebuild managed public keys for each EC publication; captured entries can pin an operation. */
	publicationMetadata?(
		context: EntityContext,
		entries?: ReadonlyMap<string, import("@oidfed/crypto").KeyringEntry>,
	): Promise<Record<string, unknown>>;
	/** Validate the final composed role block before its host publishes metadata. */
	validateMetadata?(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
}
