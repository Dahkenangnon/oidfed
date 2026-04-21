import {
	decodeEntityStatement,
	type EntityId,
	entityId,
	err,
	FederationErrorCode,
	federationError,
	fetchEntityConfiguration,
	type HttpClient,
	ok,
	type Result,
	resolveTrustChains,
	type TrustAnchorSet,
	type TrustChainResult,
} from "@oidfed/core";
import type { Config } from "../config.js";
import { extractJwks } from "./entity-id.js";

/**
 * Build a TrustAnchorSet by fetching each trust anchor's Entity Configuration
 * and extracting its JWKS. This is required for `validateTrustChain` to verify
 * the TA's self-signed EC signature.
 */
export async function buildTrustAnchors(
	anchorIds: readonly string[],
	httpClient: HttpClient,
): Promise<Result<TrustAnchorSet>> {
	const anchors = new Map<
		EntityId,
		Readonly<{ jwks: { keys: readonly Record<string, unknown>[] } }>
	>();
	for (const anchor of anchorIds) {
		let eid: EntityId;
		try {
			eid = entityId(anchor);
		} catch {
			return err(
				federationError(FederationErrorCode.InvalidRequest, `Invalid trust anchor ID: ${anchor}`),
			);
		}

		const ecResult = await fetchEntityConfiguration(eid, { httpClient });
		if (!ecResult.ok) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					`Failed to fetch entity configuration for trust anchor ${anchor}: ${ecResult.error.description}`,
				),
			);
		}

		const decoded = decodeEntityStatement(ecResult.value);
		if (!decoded.ok) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					`Failed to decode entity configuration for trust anchor ${anchor}: ${decoded.error.description}`,
				),
			);
		}

		const payload = decoded.value.payload as Record<string, unknown>;
		const jwksResult = extractJwks(payload);
		if (!jwksResult.ok) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					`Trust anchor ${anchor} missing required jwks: ${jwksResult.error.description}`,
				),
			);
		}
		anchors.set(eid, { jwks: jwksResult.value });
	}
	return ok(anchors as unknown as TrustAnchorSet);
}

export function resolveAnchorIds(args: readonly string[], config: Config): readonly string[] {
	return args.length > 0 ? args : config.trust_anchors.map((ta) => ta.entity_id);
}

export function requireAnchorIds(
	args: readonly string[],
	config: Config,
): Result<readonly string[]> {
	const anchorIds = resolveAnchorIds(args, config);
	if (anchorIds.length === 0) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"No trust anchors specified. Use --trust-anchor or configure trust_anchors in config.",
			),
		);
	}
	return ok(anchorIds);
}

export interface ResolvedTrustData {
	readonly anchors: TrustAnchorSet;
	readonly result: TrustChainResult;
}

/**
 * Build trust anchors, resolve trust chains, and check that at least one chain exists.
 *
 * Shared by resolve, chain, validate, and expiry CLI commands.
 */
export async function resolveOrError(
	eid: EntityId,
	anchorIds: readonly string[],
	httpClient: HttpClient,
	maxChainDepth?: number,
): Promise<Result<ResolvedTrustData>> {
	const anchorsResult = await buildTrustAnchors(anchorIds, httpClient);
	if (!anchorsResult.ok) return anchorsResult;

	const resolved = await resolveTrustChains(eid, anchorsResult.value, {
		httpClient,
		...(maxChainDepth !== undefined ? { maxChainDepth } : {}),
	});

	if (resolved.chains.length === 0) {
		const errorMsg = resolved.errors.map((e) => e.description).join("; ");
		return err(
			federationError(FederationErrorCode.InvalidTrustChain, `No trust chains found: ${errorMsg}`),
		);
	}

	return ok({ anchors: anchorsResult.value, result: resolved });
}
