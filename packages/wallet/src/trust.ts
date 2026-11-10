import {
	DEFAULT_MAX_CHAIN_LENGTH,
	DEFAULT_MAX_RESPONSE_BYTES,
	entityId,
	err,
	FederationErrorCode,
	type FederationOptions,
	InternalErrorCode,
	type JWKSet,
	JWKSetSchema,
	MemoryCache,
	ok,
	type PreparedTrustChain,
	prepareTrustChainValidation,
	type Result,
	resolveEntityKeys,
	resolveTrustChains,
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
	let remaining = options.maxTotalFetches ?? 50;
	if (!Number.isSafeInteger(remaining) || remaining <= 0)
		return failure("maxTotalFetches must be a positive safe integer");
	const client = options.httpClient ?? fetch;
	const state = { exhausted: false };
	const scoped = {
		...options,
		cache: options.cache ?? new MemoryCache(options.clock ? { clock: options.clock } : undefined),
		httpClient: async (input: string | URL | Request, init?: RequestInit) => {
			if (options.offline) throw new Error("Offline operation cannot access the network");
			if (options.signal?.aborted) throw options.signal.reason ?? new Error("Operation cancelled");
			if (remaining-- <= 0) {
				state.exhausted = true;
				throw new Error("Wallet operation fetch budget exhausted");
			}
			return client(input, init);
		},
	};
	operationStates.set(scoped, state);
	return ok(scoped);
}

const operationStates = new WeakMap<object, { exhausted: boolean }>();
/** Partial discovery must never turn a shared resource limit into success. */
export function operationExhausted(options: WalletTrustOptions): boolean {
	return operationStates.get(options)?.exhausted ?? false;
}

interface ChainCandidate {
	readonly statements: readonly string[];
	readonly entityConfigurations: FederationOptions["entityConfigurations"];
}

export async function candidates(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
): Promise<Result<readonly ChainCandidate[]>> {
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
		return ok([{ statements: supplied, entityConfigurations: options.entityConfigurations }]);
	}
	if (options.offline) return failure("Offline operation requires a supplied trust chain");
	const resolved = await resolveTrustChains(entityId(id), anchors, options);
	if (options.signal?.aborted) return failure("Operation cancelled");
	if (!resolved.chains.length)
		return err(
			resolved.errors[0] ?? {
				code: InternalErrorCode.TrustChainInvalid,
				description: "No trust chain found",
			},
		);
	return ok(
		[...resolved.chains]
			.sort((a, b) => a.statements.length - b.statements.length)
			.map((chain) => ({
				statements: chain.statements,
				entityConfigurations: chain.entityConfigurations ?? options.entityConfigurations,
			})),
	);
}

export function roleMetadata(
	type: WalletRoleType,
	id: string,
	chain: Pick<ValidatedTrustChain, "entityId" | "resolvedMetadata">,
): Result<Record<string, unknown>> {
	if (chain.entityId !== id)
		return failure("Trust chain subject does not match the requested entity");
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
): AsyncGenerator<Result<readonly ChainCandidate[]>> {
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
		yield await candidates(id, anchors, { ...options, trustChain: headerChain });
		if (options.offline) return;
	}
	yield await candidates(id, anchors, options);
}

export async function trustedEntity(
	type: WalletRoleType,
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
	headerChain?: readonly string[],
): Promise<Result<TrustedWalletEntity>> {
	let last = "No valid wallet trust chain";
	for await (const paths of candidateAttempts(id, anchors, options, headerChain)) {
		if (!paths.ok) return paths;
		for (const path of paths.value) {
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
			if (options.signal?.aborted) return failure("Operation cancelled");
			return ok({ entityId: id, metadata: metadata.value, trustChain: checked.chain });
		}
	}
	return err({ code: InternalErrorCode.TrustChainInvalid, description: last });
}

export async function prepareVerifier(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
	headerChain?: readonly string[],
): Promise<Result<PreparedTrustChain>> {
	let last = "No valid verifier chain";
	for await (const paths of candidateAttempts(id, anchors, options, headerChain)) {
		if (!paths.ok) return paths;
		for (const path of paths.value) {
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
			if (metadata.ok) return checked;
			last = metadata.error.description;
		}
	}
	return err({ code: InternalErrorCode.TrustChainInvalid, description: last });
}

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
	// Wallet Federation §6.3.1 requires unique identifiers for verifier keys,
	// including keys obtained through the shared protocol-key resolver.
	if (type === "openid_credential_verifier" && !JWKSetSchema.safeParse(keys).success) {
		return failure("Credential Verifier keys must have unique, nonempty kid values");
	}
	return ok(keys);
}
