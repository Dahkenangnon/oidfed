/** Wallet participant trust, supplied evidence, protocol keys, and shared operation limits. */

import {
	createTrustChainOperation,
	DEFAULT_MAX_CHAIN_LENGTH,
	DEFAULT_MAX_RESPONSE_BYTES,
	decodeEntityStatement,
	entityId,
	err,
	FederationErrorCode,
	type FederationOptions,
	InternalErrorCode,
	type JWKSet,
	JWKSetSchema,
	MemoryCache,
	ok,
	type ParsedEntityStatement,
	type PreparedTrustChain,
	prepareTrustChainValidation,
	type Result,
	resolveEntityKeys,
	resolveTrustChains,
	safeLogger,
	selectTrustChain,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	validateTrustChain,
} from "@oidfed/core";
import { effectiveRoleSchemas, type WalletRoleType } from "./metadata.js";

export interface WalletTrustOptions extends FederationOptions {
	/** Local anchor configuration for signed-object creation and role defaults. */
	readonly trustAnchors?: TrustAnchorSet;
	/** Preconstructed statements for the target; untrusted until validation succeeds. */
	readonly trustChain?: readonly string[];
	/** Additional supplied chains, keyed by their subjects, for offline integrations. */
	readonly entityChains?: ReadonlyMap<string, readonly string[]>;
	/** Block library network calls. Multi-hop chains also need intermediate ECs in entityConfigurations or a preloaded cache. */
	readonly offline?: boolean;
	readonly trustMarkIssuerKeys?: ReadonlyMap<string, JWKSet>;
}

export interface TrustedWalletEntity {
	readonly entityId: string;
	readonly metadata: Readonly<Record<string, unknown>>;
	readonly trustChain: ValidatedTrustChain;
}

export function failure(description: string): Result<never> {
	return err({ code: FederationErrorCode.InvalidRequest, description });
}

/** Keep one fetch budget across discovery, external AS discovery, and protocol-key lookups. */
export function operationOptions<T extends WalletTrustOptions>(options: T): Result<T> {
	if (options.httpClient && operationStates.has(options.httpClient)) return ok(options);
	const operation = createTrustChainOperation(options);
	if (!operation.ok) return operation;
	const client = operation.value.options.httpClient;
	if (!client) return failure("Missing operation transport");
	const scoped = {
		...options,
		cache: options.cache ?? new MemoryCache(options.clock ? { clock: options.clock } : undefined),
		httpClient: async (input: string | URL | Request, init?: RequestInit) => {
			if (options.offline) {
				safeLogger(options.logger)?.warn(
					"Supply the missing federation evidence or protocol keys for offline trust evaluation",
				);
			}
			return client(input, init);
		},
	};
	operationStates.set(scoped.httpClient, operation.value.exhausted);
	return ok(scoped);
}

// Options are copied for nested discoveries; the shared transport retains its budget identity.
const operationStates = new WeakMap<object, () => boolean>();
/** Partial discovery must never turn a shared resource limit into success. */
export function operationExhausted(options: WalletTrustOptions): boolean {
	return (
		options.signal?.aborted === true ||
		(options.httpClient ? (operationStates.get(options.httpClient)?.() ?? false) : false)
	);
}

interface ChainCandidate {
	readonly statements: readonly string[];
	readonly entityConfigurations: FederationOptions["entityConfigurations"];
}

interface ChainCandidates {
	readonly chains: readonly ChainCandidate[];
	readonly incomplete: boolean;
	readonly source: "supplied" | "hint" | "discovery";
}

/** Collect supplied or discovered target chains without treating them as validated evidence. */
export async function candidates(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
): Promise<Result<ChainCandidates>> {
	try {
		entityId(id);
	} catch {
		return failure("Invalid federation entity identifier");
	}
	if (!anchors.size) return failure("Pinned trust anchors are required");
	if (options.signal?.aborted) return failure("Operation cancelled");
	const supplied = options.trustChain ?? options.entityChains?.get(id);
	if (supplied) {
		const maxLength = options.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH;
		if (!Number.isSafeInteger(maxLength) || maxLength <= 0 || supplied.length > maxLength)
			return failure("Invalid or exceeded maxChainLength");
		const bytes = supplied.reduce((total, jwt) => total + jwt.length, 0);
		if (
			!supplied.length ||
			supplied.length > (options.maxChainDepth ?? 8) + 2 ||
			bytes > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
		)
			return failure("Supplied chain exceeds configured limits");
		return ok({
			chains: [{ statements: supplied, entityConfigurations: options.entityConfigurations }],
			incomplete: false,
			source: "supplied",
		});
	}
	if (options.offline) {
		safeLogger(options.logger)?.warn("Supply a trust chain for offline trust evaluation");
		return failure("Offline operation requires a supplied trust chain");
	}
	const resolved = await resolveTrustChains(entityId(id), anchors, options);
	if (options.signal?.aborted) return failure("Operation cancelled");
	if (operationExhausted(options) || (resolved.incomplete && options.chainSelection))
		return failure("Trust chain discovery was incomplete");
	if (!resolved.chains.length)
		return err(
			resolved.errors[0] ?? {
				code: InternalErrorCode.TrustChainInvalid,
				description: "No trust chain found",
			},
		);
	return ok({
		incomplete: resolved.incomplete === true,
		source: "discovery",
		chains: [...resolved.chains]
			.sort((a, b) => a.statements.length - b.statements.length)
			.map((chain) => ({
				statements: chain.statements,
				entityConfigurations: chain.entityConfigurations ?? options.entityConfigurations,
			})),
	});
}

/**
 * Validate effective metadata for the requested wallet role and bind issuer identity where
 * applicable.
 */
export function roleMetadata(
	type: WalletRoleType,
	id: string,
	chain: {
		readonly entityId: string;
		readonly resolvedMetadata: Readonly<Record<string, unknown>>;
		readonly statements?: readonly (ParsedEntityStatement | string)[];
		readonly discovery?: { readonly trustChain: ValidatedTrustChain };
	},
): Result<Record<string, unknown>> {
	if (chain.entityId !== id)
		return failure("Trust chain subject does not match the requested entity");
	if (type === "openid_credential_issuer") {
		// Wallet §6.2.1 binds each supplied declaration, not just the final policy output.
		// Resolver assessments authenticate these statements through the resolver response.
		for (const statement of chain.statements ?? chain.discovery?.trustChain.statements ?? []) {
			const decoded =
				typeof statement === "string" ? decodeEntityStatement(statement) : ok(statement);
			if (!decoded.ok) return failure("Invalid Credential Issuer statement evidence");
			const payload = decoded.value.payload;
			const metadata = payload.metadata?.openid_credential_issuer;
			if (
				metadata &&
				Object.hasOwn(metadata, "credential_issuer") &&
				metadata.credential_issuer !== payload.sub
			)
				return failure("credential_issuer must equal the Entity Statement subject");
		}
	}
	const parsed = effectiveRoleSchemas[type].safeParse(chain.resolvedMetadata[type]);
	if (!parsed.success)
		return err({
			code: FederationErrorCode.InvalidMetadata,
			description:
				chain.resolvedMetadata[type] === undefined
					? `Entity ${id} publishes no ${type} metadata`
					: `Invalid ${type} metadata for ${id}: ${parsed.error.issues.map((issue) => `${issue.path.join(".") || type}: ${issue.message}`).join(", ")}`,
		});
	if (type === "openid_credential_issuer" && parsed.data.credential_issuer !== id)
		return failure("credential_issuer must equal the federation entity identifier");
	return ok(parsed.data);
}

/**
 * Wallet §9 defines embedded chains as hints. Explicit caller evidence stays
 * authoritative; an unusable hint can be replaced through bounded online discovery.
 * Discovery starts only after the consumer has tried the hinted chain.
 */
async function* candidateAttempts(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
	headerChain?: readonly string[],
): AsyncGenerator<Result<ChainCandidates>> {
	if (headerChain !== undefined) {
		const maxLength = options.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH;
		if (!Number.isSafeInteger(maxLength) || maxLength <= 0 || headerChain.length > maxLength) {
			yield failure("Invalid or exceeded maxChainLength");
			return;
		}
		if (
			!headerChain.length ||
			headerChain.length > (options.maxChainDepth ?? 8) + 2 ||
			headerChain.reduce((total, jwt) => total + jwt.length, 0) >
				(options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
		) {
			yield failure("Embedded chain exceeds configured limits");
			return;
		}
	}
	if (options.trustChain !== undefined || options.entityChains?.has(id)) {
		yield await candidates(id, anchors, options);
		return;
	}
	if (headerChain !== undefined) {
		// candidates also checks the subject identifier, anchor configuration and cancellation.
		const hinted = await candidates(id, anchors, { ...options, trustChain: headerChain });
		yield hinted.ok ? ok({ ...hinted.value, source: "hint" }) : hinted;
		if (options.offline) return;
	}
	yield await candidates(id, anchors, options);
}

/** Validate and select participant trust with effective wallet-role metadata. */
export async function trustedEntity(
	type: WalletRoleType,
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
	headerChain?: readonly string[],
): Promise<Result<TrustedWalletEntity>> {
	safeLogger(options?.logger)?.debug("Validating wallet federation trusted entity evidence");

	let last = "No valid wallet trust chain";
	for await (const paths of candidateAttempts(id, anchors, options, headerChain)) {
		if (!paths.ok) return paths;
		const eligible: TrustedWalletEntity[] = [];
		for (const path of paths.value.chains) {
			const checked = await validateTrustChain(path.statements, anchors, {
				...options,
				entityConfigurations: path.entityConfigurations,
				verboseErrors: true,
			});
			if (!checked.valid) {
				last = checked.errors.map((error) => error.message).join("; ");
				continue;
			}
			const metadata = roleMetadata(type, id, checked.chain);
			if (!metadata.ok) {
				last = metadata.error.description;
				continue;
			}
			if (operationExhausted(options))
				return failure("Wallet operation cancelled or exhausted its fetch budget");
			safeLogger(options?.logger)?.info("Wallet entity trust validation completed");
			const entity = { entityId: id, metadata: metadata.value, trustChain: checked.chain };
			if (!options.chainSelection) return ok(entity);
			eligible.push(entity);
		}
		if (operationExhausted(options))
			return failure("Wallet operation cancelled or exhausted its fetch budget");
		if (eligible.length) {
			const selected = selectTrustChain(
				eligible.map((entity) => entity.trustChain),
				options,
			);
			if (!selected.ok) return selected;
			const chosen = eligible.find((entity) => entity.trustChain === selected.value);
			return chosen ? ok(chosen) : failure("Selected wallet chain is unavailable");
		}
	}
	safeLogger(options?.logger)?.warn("Wallet entity trust validation rejected");
	return err({ code: InternalErrorCode.TrustChainInvalid, description: last });
}

/** Prepare all eligible verifier chains, retaining deferred contextual metadata for completion. */
export async function prepareVerifierCandidates(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
	headerChain?: readonly string[],
): Promise<
	Result<{
		readonly chains: readonly PreparedTrustChain[];
		readonly source: ChainCandidates["source"];
	}>
> {
	safeLogger(options?.logger)?.debug("Preparing Credential Verifier Trust Chain validation");

	let last = "No valid verifier chain";
	for await (const paths of candidateAttempts(id, anchors, options, headerChain)) {
		if (!paths.ok) return paths;
		const eligible: PreparedTrustChain[] = [];
		for (const path of paths.value.chains) {
			const checked = await prepareTrustChainValidation(path.statements, anchors, {
				...options,
				entityConfigurations: path.entityConfigurations,
				verboseErrors: true,
				deferredClaims: [{ entityType: "openid_credential_verifier", parameter: "dcql_queries" }],
			});
			if (!checked.ok) {
				last = checked.error.description;
				continue;
			}
			const metadata = roleMetadata("openid_credential_verifier", id, checked.value);
			if (metadata.ok) {
				eligible.push(checked.value);
			} else last = metadata.error.description;
		}
		if (operationExhausted(options))
			return failure("Wallet operation cancelled or exhausted its fetch budget");
		if (eligible.length) return ok({ chains: eligible, source: paths.value.source });
	}
	safeLogger(options?.logger)?.warn("Verifier trust preparation rejected");
	return err({ code: InternalErrorCode.TrustChainInvalid, description: last });
}

/** Select prepared verifier evidence for later contextual completion. */
export async function prepareVerifier(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
	headerChain?: readonly string[],
): Promise<Result<PreparedTrustChain>> {
	const candidates = await prepareVerifierCandidates(id, anchors, options, headerChain);
	if (!candidates.ok) return candidates;
	const first = candidates.value.chains[0];
	return first ? ok(first) : failure("No verifier chain available");
}

/**
 * Resolve protocol keys from validated participant metadata, keeping Federation Entity Keys
 * separate.
 */
export async function protocolKeys(
	entity: {
		readonly metadata: Readonly<Record<string, unknown>>;
		readonly trustChain: Pick<ValidatedTrustChain, "resolvedMetadata" | "statements">;
	},
	type: WalletRoleType,
	options: WalletTrustOptions,
): Promise<Result<JWKSet>> {
	const metadata = entity.trustChain.resolvedMetadata[type];
	if (!metadata) return failure("Missing protocol metadata");
	// An effective inline set is authoritative, including an immediate superior's replacement.
	const selected = metadata.jwks !== undefined ? { jwks: metadata.jwks } : metadata;
	if (options.offline && selected.jwks === undefined)
		return failure("Offline verification requires locally available protocol keys");
	const federationKeys = entity.trustChain.statements[0]?.payload.jwks;
	if (!federationKeys) return failure("Missing authenticated federation keys");
	const owner = entity.trustChain.statements[0]?.payload.sub;
	if (!owner) return failure("Missing authenticated key owner");
	const resolved = await resolveEntityKeys(selected, federationKeys, {
		...options,
		expectedIssuer: owner,
		expectedOwner: owner,
	});
	if (!resolved.ok) return resolved;
	const keys = { keys: resolved.value.keys };
	if (keys.keys.length === 0) return failure("Verification requires usable protocol keys");
	// Wallet Federation §6.3.1 requires unique identifiers for verifier keys,
	// including keys obtained through the shared protocol-key resolver.
	if (type === "openid_credential_verifier" && !JWKSetSchema.safeParse(keys).success) {
		return failure("Credential Verifier keys must have unique, nonempty kid values");
	}
	return ok(keys);
}
