/** Shared registration trust, supplied-chain, and common-anchor selection helpers. */

import {
	createTrustChainOperation,
	type EntityId,
	entityId,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	InternalErrorCode,
	ok,
	type Result,
	resolveTrustChainForAnchor,
	resolveTrustChains,
	safeLogger,
	selectTrustChain,
	shortestChain,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	type ValidationResult,
	validateTrustChain,
} from "@oidfed/core";
import { effectiveMetadata } from "../metadata.js";
import { oidcRegistrationProfile, type RegistrationProfile } from "./profile.js";

/** Extracts `client_registration_types_supported` from OP metadata. */
export function getRegistrationTypes(opMeta: Record<string, unknown> | undefined): string[] {
	return (opMeta?.client_registration_types_supported as string[] | undefined) ?? [];
}

const REQUIRED_TRUST_ANCHORS_MESSAGE =
	"OP-side registration requires a non-empty Trust Anchor set.";

type TrustAnchorConfig = TrustAnchorSet extends ReadonlyMap<string, infer Config> ? Config : never;

/** Parse the registration trust-chain array without treating its statements as authenticated. */
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

/** Return an error when no local Trust Anchor configuration is available. */
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

/** Require configured anchors for a role operation; missing configuration throws. */
export function assertNonEmptyTrustAnchors(
	trustAnchors: TrustAnchorSet | undefined,
): TrustAnchorSet {
	const result = requireNonEmptyTrustAnchors(trustAnchors);
	if (!result.ok) {
		throw new Error(result.error.description);
	}
	return result.value;
}

/**
 * Validate supplied statements using the caller's anchors and preserve registration-specific
 * context.
 */
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

type ValidRegistrationChain = {
	readonly statements: readonly string[];
	readonly chain: ValidatedTrustChain;
};

export interface SharedRegistrationTrustChains {
	readonly rpChainStatements: readonly string[];
	readonly rpChain: ValidatedTrustChain;
	readonly opChain: ValidatedTrustChain;
	readonly trustAnchorId: EntityId;
}

async function resolveValidRegistrationChains(
	subject: EntityId,
	trustAnchors: TrustAnchorSet,
	options: FederationOptions | undefined,
	label: string,
	validateCandidate?: (
		statements: readonly string[],
		validationOptions: FederationOptions,
	) => Promise<ValidationResult>,
	profile: RegistrationProfile = oidcRegistrationProfile,
): Promise<Result<readonly ValidRegistrationChain[], FederationError>> {
	const operation = createTrustChainOperation(options);
	if (!operation.ok) return operation;
	options = operation.value.options;
	const chainResult = await resolveTrustChains(subject, trustAnchors, options);

	if (chainResult.chains.length === 0) {
		const errorMsgs = chainResult.errors.map((e) => e.description).join("; ");
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`Failed to resolve trust chain for ${label}: ${errorMsgs || "no chains found"}`,
			),
		);
	}

	const validChains: ValidRegistrationChain[] = [];
	let metadataError: FederationError | undefined;
	for (const chain of chainResult.chains) {
		const validation = validateCandidate
			? await validateCandidate(chain.statements, {
					...options,
					entityConfigurations: chain.entityConfigurations,
				})
			: await validateTrustChain(chain.statements, trustAnchors, {
					...options,
					entityConfigurations: chain.entityConfigurations,
				});
		if (validation.valid) {
			const type = label === "OP" ? profile.providerType : profile.clientType;
			const parsed = effectiveMetadata(
				type,
				validation.chain.resolvedMetadata[type],
				validation.chain.entityId,
			);
			if (!parsed.ok) {
				metadataError ??= parsed.error;
				continue;
			}
			validChains.push({ statements: chain.statements, chain: validation.chain });
		}
	}

	if (operation.value.exhausted() || (options?.chainSelection && chainResult.incomplete))
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				"Trust chain discovery was incomplete",
			),
		);
	if (validChains.length === 0) {
		if (metadataError) return err(metadataError);
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`No valid trust chains found for ${label}`,
			),
		);
	}

	return ok(validChains);
}

/** Select validated client and provider chains sharing an anchor before registration proceeds. */
export async function selectSharedRegistrationTrustChains(
	rpEntityId: EntityId,
	opEntityId: EntityId,
	preferredOpChain: ValidatedTrustChain,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
	selection: {
		readonly validateRpCandidate?: (
			statements: readonly string[],
			validationOptions: FederationOptions,
		) => Promise<ValidationResult>;
		readonly allowAlternativeProvider?: boolean;
		readonly profile?: RegistrationProfile;
	} = {},
): Promise<Result<SharedRegistrationTrustChains, FederationError>> {
	const profile = selection.profile ?? oidcRegistrationProfile;
	// Check the provider before invoking callbacks that may sign registration requests.
	const preferredMetadata = effectiveMetadata(
		profile.providerType,
		preferredOpChain.resolvedMetadata[profile.providerType],
		opEntityId,
	);
	if (!preferredMetadata.ok && !selection.allowAlternativeProvider) return preferredMetadata;
	const alternatives = !preferredMetadata.ok
		? await resolveValidRegistrationChains(
				opEntityId,
				trustAnchors,
				options,
				"OP",
				undefined,
				profile,
			)
		: undefined;
	if (alternatives && !alternatives.ok)
		return err(preferredMetadata.ok ? alternatives.error : preferredMetadata.error);
	const rpChainsResult = await resolveValidRegistrationChains(
		rpEntityId,
		trustAnchors,
		options,
		"RP",
		selection.validateRpCandidate,
		profile,
	);
	if (!rpChainsResult.ok) return rpChainsResult;
	const rpChains = rpChainsResult.value;

	const preferredRpChains = rpChains.filter(
		(candidate) => candidate.chain.trustAnchorId === preferredOpChain.trustAnchorId,
	);
	if (preferredMetadata.ok && preferredRpChains.length > 0) {
		const selected = selectTrustChain(
			preferredRpChains.map((candidate) => candidate.chain),
			options,
			shortestChain,
		);
		if (!selected.ok) return selected;
		const rpChain = preferredRpChains.find((candidate) => candidate.chain === selected.value);
		if (!rpChain)
			return err(
				federationError(FederationErrorCode.InvalidTrustChain, "Selected RP chain is unavailable"),
			);
		return ok({
			rpChainStatements: rpChain.statements,
			rpChain: rpChain.chain,
			opChain: preferredOpChain,
			trustAnchorId: preferredOpChain.trustAnchorId,
		});
	}

	const opChainsResult =
		alternatives ??
		(await resolveValidRegistrationChains(
			opEntityId,
			trustAnchors,
			options,
			"OP",
			undefined,
			profile,
		));
	if (!opChainsResult.ok) return opChainsResult;

	const eligibleRp = rpChains.filter((rp) =>
		opChainsResult.value.some((op) => op.chain.trustAnchorId === rp.chain.trustAnchorId),
	);
	if (options?.chainSelection && eligibleRp.length) {
		const selected = selectTrustChain(
			eligibleRp.map((candidate) => candidate.chain),
			options,
		);
		if (!selected.ok) return selected;
		const index = eligibleRp.findIndex((candidate) => candidate.chain === selected.value);
		eligibleRp.unshift(...eligibleRp.splice(index, 1));
	}
	for (const rpChain of eligibleRp) {
		const matchingOpChains = opChainsResult.value.filter(
			(candidate) => candidate.chain.trustAnchorId === rpChain.chain.trustAnchorId,
		);
		if (matchingOpChains.length > 0) {
			const selected = selectTrustChain(
				matchingOpChains.map((candidate) => candidate.chain),
				options,
				shortestChain,
			);
			if (!selected.ok) return selected;
			const opChain = matchingOpChains.find((candidate) => candidate.chain === selected.value);
			if (!opChain)
				return err(
					federationError(
						FederationErrorCode.InvalidTrustChain,
						"Selected OP chain is unavailable",
					),
				);
			return ok({
				rpChainStatements: rpChain.statements,
				rpChain: rpChain.chain,
				opChain: opChain.chain,
				trustAnchorId: rpChain.chain.trustAnchorId,
			});
		}
	}

	return err(
		federationError(
			FederationErrorCode.InvalidTrustAnchor,
			"No shared Trust Anchor between RP and OP",
		),
	);
}

/**
 * Resolve client chains and select one using the configured strategy.
 *
 * Resolves the client chain for automatic registration.
 */
export async function resolveAndValidateBestChain(
	rpEntityId: EntityId,
	trustAnchors: TrustAnchorSet,
	options: FederationOptions,
	profile: RegistrationProfile = oidcRegistrationProfile,
): Promise<Result<ValidatedTrustChain, FederationError>> {
	const candidates = await resolveValidRegistrationChains(
		rpEntityId,
		trustAnchors,
		options,
		"RP",
		undefined,
		profile,
	);
	if (!candidates.ok) return candidates;
	return selectTrustChain(
		candidates.value.map((candidate) => candidate.chain),
		options,
		shortestChain,
	);
}

/** Build matching trust_chain and optional peer_trust_chain headers before signing. */
export async function registrationChainHeaders(
	selectedChain: readonly string[],
	selectedTrustAnchorId: EntityId | undefined,
	providerEntityId: EntityId,
	includePeerTrustChain: boolean | undefined,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<Result<Record<string, unknown>>> {
	const extraHeaders: Record<string, unknown> = {};
	if (selectedChain.length > 0) {
		extraHeaders.trust_chain = selectedChain;
	}

	if (includePeerTrustChain) {
		if (!selectedTrustAnchorId) {
			safeLogger(options?.logger)?.warn(
				"includePeerTrustChain requires a selected RP Trust Anchor",
			);
			return err(
				federationError(
					InternalErrorCode.TrustAnchorUnknown,
					"includePeerTrustChain requires a selected RP Trust Anchor; no valid RP chain was built",
				),
			);
		}
		const peerChainResult = await resolveTrustChainForAnchor(
			providerEntityId,
			selectedTrustAnchorId,
			trustAnchors,
			options,
		);
		if (!peerChainResult.ok) {
			safeLogger(options?.logger)?.warn(
				"Cannot build peer_trust_chain to the selected Trust Anchor",
			);
			return err(
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`includePeerTrustChain: cannot build peer Trust Chain for ${providerEntityId} ending at ${selectedTrustAnchorId}: ${peerChainResult.error.description}`,
				),
			);
		}
		extraHeaders.peer_trust_chain = peerChainResult.value;
	}

	return ok(extraHeaders);
}
