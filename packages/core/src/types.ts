/** Branded types for compile-time safety: EntityId, DiscoveryResult, and Result/Err helpers. */
import type { InternalErrorCode } from "./constants.js";
import type { FederationError } from "./errors.js";
import type { EntityStatementPayload, JWKSet } from "./schemas/index.js";

declare const EntityIdBrand: unique symbol;
export type EntityId = string & { readonly [EntityIdBrand]: true };

/** Parse and validate a string as an HTTPS Entity Identifier, throwing on invalid input. */
export function entityId(value: string): EntityId {
	if (value.length > 2048) throw new TypeError("Entity ID must not exceed 2048 characters");
	const url = new URL(value);
	if (url.protocol !== "https:") throw new TypeError("Entity ID must be HTTPS");
	if (url.username || url.password) throw new TypeError("Entity ID must not contain credentials");
	if (url.search || url.hash)
		throw new TypeError("Entity ID must not contain query parameters or fragments");
	return value as EntityId;
}

/** Check whether a string is a valid Entity Identifier without throwing. */
export function isValidEntityId(value: string): value is EntityId {
	if (value.length > 2048) return false;
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash;
	} catch {
		return false;
	}
}

declare const Unverified: unique symbol;
export type ParsedEntityStatement = {
	readonly header: Record<string, unknown>;
	readonly payload: EntityStatementPayload;
};
export type UnverifiedEntityStatement = ParsedEntityStatement & {
	readonly [Unverified]: true;
};

export type HttpClient = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface Clock {
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
	[Symbol.asyncDispose]?(): Promise<void>;
}

export interface Logger {
	debug(msg: string, context?: Record<string, unknown>): void;
	info(msg: string, context?: Record<string, unknown>): void;
	warn(msg: string, context?: Record<string, unknown>): void;
	error(msg: string, context?: Record<string, unknown>): void;
}

export interface FederationOptions {
	httpClient?: HttpClient;
	clock?: Clock;
	cache?: CacheProvider;
	logger?: Logger;
	httpTimeoutMs?: number;
	clockSkewSeconds?: number;
	maxChainDepth?: number;
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
	/** Maximum total HTTP fetches across entire trust chain resolution. Default: 50. */
	maxTotalFetches?: number;
}

export type TrustAnchorSet = ReadonlyMap<EntityId, Readonly<{ jwks: JWKSet }>>;

export interface TrustChain {
	readonly statements: ReadonlyArray<string>;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata?: Readonly<Record<string, unknown>>;
}

export interface TrustChainResult {
	readonly chains: ReadonlyArray<TrustChain>;
	readonly errors: ReadonlyArray<FederationError>;
}

export interface ValidatedTrustChain {
	readonly statements: ReadonlyArray<ParsedEntityStatement>;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata: Readonly<Record<string, Record<string, unknown>>>;
	readonly trustMarks: ReadonlyArray<ValidatedTrustMark>;
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

export interface ValidatedTrustMark {
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
