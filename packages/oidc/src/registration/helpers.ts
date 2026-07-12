import {
	type EntityId,
	entityId,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	ok,
	type Result,
	resolveTrustChains,
	shortestChain,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	validateTrustChain,
} from "@oidfed/core";

/** Extracts `client_registration_types_supported` from OP metadata. */
export function getRegistrationTypes(opMeta: Record<string, unknown> | undefined): string[] {
	return (opMeta?.client_registration_types_supported as string[] | undefined) ?? [];
}

const REQUIRED_TRUST_ANCHORS_MESSAGE =
	"OP-side registration requires a non-empty Trust Anchor set.";

type TrustAnchorConfig = TrustAnchorSet extends ReadonlyMap<string, infer Config> ? Config : never;

export function parseTrustChainJsonBody(body: string): Result<readonly string[], FederationError> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(body);
	} catch {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Invalid trust-chain+json body"),
		);
	}

	if (
		!Array.isArray(parsed) ||
		parsed.length === 0 ||
		!parsed.every((statement) => typeof statement === "string")
	) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"trust-chain+json must be a non-empty array of JWT strings",
			),
		);
	}

	return ok(parsed);
}

export function requireNonEmptyTrustAnchors(
	trustAnchors: TrustAnchorSet | undefined,
): Result<TrustAnchorSet, FederationError> {
	if (!trustAnchors || trustAnchors.size === 0) {
		return err(
			federationError(FederationErrorCode.InvalidTrustChain, REQUIRED_TRUST_ANCHORS_MESSAGE),
		);
	}
	const normalized = new Map<string, TrustAnchorConfig>();
	for (const [anchorId, config] of trustAnchors) {
		try {
			normalized.set(entityId(anchorId), config);
		} catch (cause) {
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					`Invalid Trust Anchor entity ID '${anchorId}'.`,
					cause,
				),
			);
		}
	}
	return ok(normalized);
}

export function assertNonEmptyTrustAnchors(
	trustAnchors: TrustAnchorSet | undefined,
): TrustAnchorSet {
	const result = requireNonEmptyTrustAnchors(trustAnchors);
	if (!result.ok) {
		throw new Error(result.error.description);
	}
	return result.value;
}

export async function validateSuppliedTrustChain(
	chain: readonly string[] | undefined,
	trustAnchors: TrustAnchorSet,
	options: FederationOptions & {
		readonly expectedSubject: EntityId;
		readonly label: string;
		readonly explicitRegistrationAudience?: EntityId;
	},
): Promise<Result<ValidatedTrustChain, FederationError>> {
	if (!Array.isArray(chain) || chain.length === 0 || !chain.every((s) => typeof s === "string")) {
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`${options.label} must be a non-empty array of JWT strings`,
			),
		);
	}

	const validation = await validateTrustChain(chain, trustAnchors, {
		...options,
		verboseErrors: true,
		...(options.explicitRegistrationAudience !== undefined
			? { explicitRegistrationAudience: options.explicitRegistrationAudience }
			: {}),
	});
	if (!validation.valid) {
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`${options.label} validation failed: ${validation.errors[0]?.message ?? "unknown error"}`,
			),
		);
	}

	if (validation.chain.entityId !== options.expectedSubject) {
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`${options.label} subject '${validation.chain.entityId}' does not match expected subject '${options.expectedSubject}'`,
			),
		);
	}

	return ok(validation.chain);
}

/**
 * Resolve trust chains for an entity and return the shortest valid chain.
 *
 * Shared by automatic and explicit registration flows.
 */
export async function resolveAndValidateBestChain(
	rpEntityId: EntityId,
	trustAnchors: TrustAnchorSet,
	options: FederationOptions,
): Promise<Result<ValidatedTrustChain, FederationError>> {
	const chainResult = await resolveTrustChains(rpEntityId, trustAnchors, options);

	if (chainResult.chains.length === 0) {
		const errorMsgs = chainResult.errors.map((e) => e.description).join("; ");
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`Failed to resolve trust chain for RP: ${errorMsgs || "no chains found"}`,
			),
		);
	}

	const validChains: ValidatedTrustChain[] = [];
	for (const chain of chainResult.chains) {
		const result = await validateTrustChain(chain.statements, trustAnchors, options);
		if (result.valid) {
			validChains.push(result.chain);
		}
	}

	if (validChains.length === 0) {
		return err(
			federationError(FederationErrorCode.InvalidTrustChain, "No valid trust chains found for RP"),
		);
	}

	return ok(shortestChain(validChains));
}
