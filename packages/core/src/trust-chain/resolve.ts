/** Bottom-up trust chain resolution: walks authority_hints to discover all possible chains. */
import {
	DEFAULT_MAX_AUTHORITY_HINTS,
	DEFAULT_MAX_CHAIN_DEPTH,
	InternalErrorCode,
} from "../constants.js";
import { type FederationError, federationError } from "../errors.js";
import { decodeEntityStatement } from "../jose/verify.js";
import type {
	EntityId,
	FederationOptions,
	TrustAnchorSet,
	TrustChain,
	TrustChainResult,
} from "../types.js";
import { fetchEntityConfiguration, fetchSubordinateStatement } from "./fetch.js";
import { calculateChainExpiration } from "./validate.js";

/** Create a concurrency limiter that allows at most `maxConcurrent` parallel executions. */
export function createConcurrencyLimiter(
	maxConcurrent: number,
): <T>(fn: () => Promise<T>) => Promise<T> {
	let active = 0;
	const queue: Array<() => void> = [];

	return async <T>(fn: () => Promise<T>): Promise<T> => {
		if (active >= maxConcurrent) {
			await new Promise<void>((resolve) => queue.push(resolve));
		}
		active++;
		try {
			return await fn();
		} finally {
			active--;
			const next = queue.shift();
			if (next) next();
		}
	};
}

/** Resolve all possible trust chains for an entity against a set of trust anchors. */
export async function resolveTrustChains(
	entityId: EntityId,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<TrustChainResult> {
	const maxDepth = options?.maxChainDepth ?? DEFAULT_MAX_CHAIN_DEPTH;
	const maxHints = options?.maxAuthorityHints ?? DEFAULT_MAX_AUTHORITY_HINTS;
	const limiter = createConcurrencyLimiter(options?.maxConcurrentFetches ?? 6);
	const maxTotalFetches = options?.maxTotalFetches ?? 50;
	const fetchBudget = { remaining: maxTotalFetches };

	const chains: TrustChain[] = [];
	const errors: FederationError[] = [];

	if (fetchBudget.remaining <= 0) {
		return {
			chains: [],
			errors: [federationError(InternalErrorCode.TrustChainInvalid, "Fetch budget exhausted")],
		};
	}
	fetchBudget.remaining--;
	const leafEcResult = await fetchEntityConfiguration(entityId, options);
	if (!leafEcResult.ok) {
		return { chains: [], errors: [leafEcResult.error] };
	}
	const leafEcJwt = leafEcResult.value;

	const leafDecoded = decodeEntityStatement(leafEcJwt);
	if (!leafDecoded.ok) {
		return { chains: [], errors: [leafDecoded.error] };
	}

	const leafPayload = leafDecoded.value.payload;
	if (leafPayload.iss !== leafPayload.sub || (leafPayload.iss as string) !== (entityId as string)) {
		return {
			chains: [],
			errors: [
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`Leaf EC identity mismatch: iss=${leafPayload.iss}, sub=${leafPayload.sub}, expected=${entityId}`,
				),
			],
		};
	}

	const hints = (leafPayload as Record<string, unknown>).authority_hints as string[] | undefined;

	if ((!hints || hints.length === 0) && trustAnchors.has(entityId)) {
		const parsed = [leafDecoded.value];
		return {
			chains: [
				{
					statements: [leafEcJwt],
					entityId,
					trustAnchorId: entityId,
					expiresAt: calculateChainExpiration(parsed),
				},
			],
			errors: [],
		};
	}

	if (!hints || hints.length === 0) {
		return {
			chains: [],
			errors: [
				federationError(
					InternalErrorCode.TrustChainInvalid,
					"Leaf has no authority_hints and is not a trust anchor",
				),
			],
		};
	}

	// Recursively walk authority_hints upward, collecting subordinate statements at each hop
	async function buildChains(
		currentEntityId: string,
		currentHints: string[],
		chainSoFar: string[],
		visited: Set<string>,
		depth: number,
	): Promise<void> {
		if (depth > maxDepth) {
			errors.push(
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`Max chain depth (${maxDepth}) exceeded`,
				),
			);
			return;
		}

		if (options?.signal?.aborted) return;

		let filteredHints = currentHints.slice(0, maxHints);
		if (options?.authorityHintFilter) {
			filteredHints = filteredHints.filter((h) => {
				try {
					return options.authorityHintFilter?.(new URL(h), currentEntityId as EntityId);
				} catch {
					return false;
				}
			});
		}

		const settled = await Promise.allSettled(
			filteredHints.map((hint) =>
				limiter(async () => {
					const branchVisited = new Set(visited);

					if (branchVisited.has(hint)) {
						errors.push(
							federationError(
								InternalErrorCode.LoopDetected,
								`Loop detected: '${hint}' already in chain`,
							),
						);
						return;
					}
					branchVisited.add(hint);

					if (fetchBudget.remaining <= 0) {
						errors.push(
							federationError(InternalErrorCode.TrustChainInvalid, "Fetch budget exhausted"),
						);
						return;
					}
					fetchBudget.remaining--;
					const hintEcResult = await fetchEntityConfiguration(hint as EntityId, options);
					if (!hintEcResult.ok) {
						errors.push(hintEcResult.error);
						return;
					}

					const hintDecoded = decodeEntityStatement(hintEcResult.value);
					if (!hintDecoded.ok) {
						errors.push(hintDecoded.error);
						return;
					}

					const hintMeta = hintDecoded.value.payload.metadata as
						| Record<string, Record<string, unknown>>
						| undefined;
					const fedEntity = hintMeta?.federation_entity;
					const fetchEndpoint = fedEntity?.federation_fetch_endpoint as string | undefined;

					if (!fetchEndpoint) {
						errors.push(
							federationError(
								InternalErrorCode.TrustChainInvalid,
								`Entity '${hint}' has no federation_fetch_endpoint in metadata`,
							),
						);
						return;
					}

					if (fetchBudget.remaining <= 0) {
						errors.push(
							federationError(InternalErrorCode.TrustChainInvalid, "Fetch budget exhausted"),
						);
						return;
					}
					fetchBudget.remaining--;
					const ssResult = await fetchSubordinateStatement(
						fetchEndpoint,
						currentEntityId as EntityId,
						options,
					);
					if (!ssResult.ok) {
						errors.push(ssResult.error);
						return;
					}

					if (trustAnchors.has(hint as EntityId)) {
						const fullChain = [...chainSoFar, ssResult.value, hintEcResult.value];
						const parsed = fullChain.map((jwt) => {
							const d = decodeEntityStatement(jwt);
							return d.ok ? d.value : null;
						});
						if (parsed.every((p) => p !== null)) {
							chains.push({
								statements: fullChain,
								entityId,
								trustAnchorId: hint as EntityId,
								expiresAt: calculateChainExpiration(parsed as NonNullable<(typeof parsed)[0]>[]),
							});
						}
						return;
					}

					const hintHints = (hintDecoded.value.payload as Record<string, unknown>)
						.authority_hints as string[] | undefined;
					if (!hintHints || hintHints.length === 0) {
						errors.push(
							federationError(
								InternalErrorCode.TrustChainInvalid,
								`Entity '${hint}' has no authority_hints and is not a trust anchor`,
							),
						);
						return;
					}

					await buildChains(
						hint,
						hintHints,
						[...chainSoFar, ssResult.value],
						branchVisited,
						depth + 1,
					);
				}),
			),
		);

		for (const result of settled) {
			if (result.status === "rejected") {
				errors.push(
					federationError(
						InternalErrorCode.Network,
						result.reason instanceof Error
							? result.reason.message
							: "Unknown error during chain resolution",
						result.reason,
					),
				);
			}
		}
	}

	const initialVisited = new Set<string>([entityId]);
	await buildChains(entityId, hints, [leafEcJwt], initialVisited, 1);

	return { chains, errors };
}
