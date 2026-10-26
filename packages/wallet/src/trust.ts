import {
	DEFAULT_MAX_RESPONSE_BYTES,
	entityId,
	err,
	FederationErrorCode,
	type FederationOptions,
	InternalErrorCode,
	type JWKSet,
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
import { roleSchemas, type WalletRoleType } from "./metadata.js";

export interface WalletTrustOptions extends FederationOptions {
	/** Local anchor configuration for signed-object creation and role defaults. */
	readonly trustAnchors?: TrustAnchorSet;
	/** Preconstructed statements for the target; untrusted until validation succeeds. */
	readonly trustChain?: readonly string[];
	/** Additional supplied chains, keyed by their subjects, for offline integrations. */
	readonly entityChains?: ReadonlyMap<string, readonly string[]>;
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
export function operationOptions(options: WalletTrustOptions = {}): WalletTrustOptions {
	let remaining = options.maxTotalFetches ?? 50;
	if (!Number.isSafeInteger(remaining) || remaining <= 0)
		throw new TypeError("maxTotalFetches must be a positive safe integer");
	const client = options.httpClient ?? fetch;
	return {
		...options,
		httpClient: async (input, init) => {
			if (options.offline) throw new Error("Offline operation cannot access the network");
			if (options.signal?.aborted) throw options.signal.reason ?? new Error("Operation cancelled");
			if (remaining-- <= 0) throw new Error("Wallet operation fetch budget exhausted");
			return client(input, init);
		},
	};
}

export async function candidates(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
): Promise<Result<readonly (readonly string[])[]>> {
	try {
		entityId(id);
	} catch {
		return failure("Invalid federation entity identifier");
	}
	if (!anchors.size) return failure("Pinned trust anchors are required");
	if (options.signal?.aborted) return failure("Operation cancelled");
	const supplied = options.trustChain ?? options.entityChains?.get(id);
	if (supplied) {
		const bytes = supplied.reduce((total, jwt) => total + jwt.length, 0);
		if (
			!supplied.length ||
			supplied.length > (options.maxChainDepth ?? 8) + 2 ||
			bytes > (options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
		)
			return failure("Supplied chain exceeds configured limits");
		return ok([supplied]);
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
			.map((chain) => chain.statements),
	);
}

export function roleMetadata(
	type: WalletRoleType,
	id: string,
	chain: Pick<ValidatedTrustChain, "entityId" | "resolvedMetadata">,
): Result<Record<string, unknown>> {
	if (chain.entityId !== id)
		return failure("Trust chain subject does not match the requested entity");
	const parsed = roleSchemas[type].safeParse(chain.resolvedMetadata[type]);
	if (!parsed.success)
		return err({ code: FederationErrorCode.InvalidMetadata, description: parsed.error.message });
	if (type === "openid_credential_issuer" && parsed.data.credential_issuer !== id)
		return failure("credential_issuer must equal the federation entity identifier");
	return ok(parsed.data);
}

export async function trustedEntity(
	type: WalletRoleType,
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
): Promise<Result<TrustedWalletEntity>> {
	const paths = await candidates(id, anchors, options);
	if (!paths.ok) return paths;
	let last = "No valid wallet trust chain";
	for (const path of paths.value) {
		const checked = await validateTrustChain(path, anchors, { ...options, verboseErrors: true });
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
	return err({ code: InternalErrorCode.TrustChainInvalid, description: last });
}

export async function prepareVerifier(
	id: string,
	anchors: TrustAnchorSet,
	options: WalletTrustOptions,
): Promise<Result<PreparedTrustChain>> {
	const paths = await candidates(id, anchors, options);
	if (!paths.ok) return paths;
	let last = "No valid verifier chain";
	for (const path of paths.value) {
		const checked = await prepareTrustChainValidation(path, anchors, {
			...options,
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
	const resolved = await resolveEntityKeys(selected, federationKeys, options);
	return resolved.ok ? ok({ keys: resolved.value.keys }) : resolved;
}
