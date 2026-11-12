/** Bottom-up trust chain resolution: walks authority_hints to discover all possible chains. */
import {
	DEFAULT_MAX_AUTHORITY_HINTS,
	DEFAULT_MAX_CHAIN_DEPTH,
	DEFAULT_MAX_RESOLUTION_STEPS,
	InternalErrorCode,
} from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "./../logging.js";
import { validateEntityStatementTimeClaims } from "../statement-validation.js";
import type {
	EntityId,
	FederationOptions,
	ParsedEntityStatement,
	TrustAnchorSet,
	TrustChain,
	TrustChainResult,
} from "../types.js";
import { fetchEntityConfiguration, fetchSubordinateStatement } from "./fetch.js";
import { calculateChainExpiration, validateEntityConfigurationPublication } from "./validate.js";

/** Create a concurrency limiter that allows at most `maxConcurrent` parallel executions. */
export function createConcurrencyLimiter(
	maxConcurrent: number,
	signal?: AbortSignal,
): <T>(fn: () => Promise<T>) => Promise<T> {
	if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent <= 0)
		throw new RangeError("maxConcurrent must be a positive safe integer");
	let active = 0;
	const queue: Array<{ resolve: () => void; reject: (reason: unknown) => void }> = [];
	const aborted = () => new DOMException("Operation aborted", "AbortError");
	const onAbort = () => {
		for (const pending of queue.splice(0)) pending.reject(aborted());
		signal?.removeEventListener("abort", onAbort);
	};
	async function acquire(): Promise<void> {
		if (signal?.aborted) throw aborted();
		if (active < maxConcurrent) {
			active++;
			return;
		}
		await new Promise<void>((resolve, reject) => {
			queue.push({ resolve, reject });
			if (queue.length === 1) signal?.addEventListener("abort", onAbort, { once: true });
			if (signal?.aborted) onAbort();
		});
	}

	return async <T>(fn: () => Promise<T>): Promise<T> => {
		await acquire();
		try {
			if (signal?.aborted) throw aborted();
			return await fn();
		} finally {
			const next = queue.shift();
			if (!queue.length) signal?.removeEventListener("abort", onAbort);
			// Transfer the occupied slot directly to a waiter before admitting new work.
			if (next) next.resolve();
			else active--;
		}
	};
}

export interface ResolveTrustChainsOptions extends FederationOptions {
	/** Start with this signed EC; its hints are traversed without fetching or caching a replacement. */
	readonly entityConfigurationJwt?: string;
	/** Expected OP audience for a supplied explicit-registration request. */
	readonly explicitRegistrationAudience?: EntityId;
}

/** Resolve all possible trust chains for an entity against a set of trust anchors. */
export async function resolveTrustChains(
	entityId: EntityId,
	trustAnchors: TrustAnchorSet,
	options?: ResolveTrustChainsOptions,
): Promise<TrustChainResult> {
	safeLogger(options?.logger)?.debug("Starting resolve trust chains");

	if (options?.signal?.aborted) {
		return {
			chains: [],
			errors: [federationError(InternalErrorCode.TrustChainInvalid, "Resolution aborted")],
			incomplete: true,
		};
	}
	if (
		options?.explicitRegistrationAudience !== undefined &&
		options.entityConfigurationJwt === undefined
	)
		return {
			chains: [],
			errors: [
				federationError(
					InternalErrorCode.TrustChainInvalid,
					"Registration audience requires a supplied Entity Configuration",
				),
			],
		};
	const maxDepth = options?.maxChainDepth ?? DEFAULT_MAX_CHAIN_DEPTH;
	const maxHints = options?.maxAuthorityHints ?? DEFAULT_MAX_AUTHORITY_HINTS;
	const maxSteps = options?.maxResolutionSteps ?? DEFAULT_MAX_RESOLUTION_STEPS;
	if (!Number.isSafeInteger(maxSteps) || maxSteps <= 0)
		throw new RangeError("maxResolutionSteps must be a positive safe integer");
	let remainingSteps = maxSteps;
	let stepLimitReported = false;
	const limiter = createConcurrencyLimiter(options?.maxConcurrentFetches ?? 6, options?.signal);
	const maxTotalFetches = options?.maxTotalFetches ?? 50;
	const fetchBudget = { remaining: maxTotalFetches };

	const chains: TrustChain[] = [];
	const errors: FederationError[] = [];
	let incomplete = false;

	// Share statement retrievals within this resolution (Federation §10.1).
	// Each candidate retains its own visited Entities; HTTP and traversal limits are separate.
	const configurations = new Map<string, Promise<Result<string>>>();
	type Configuration = { jwt: string; statement: ParsedEntityStatement };
	const authenticatedConfigurations = new Map<string, Promise<Result<Configuration>>>();
	const configurationJwts = new Map<string, string>();
	const statements = new Map<string, Promise<Result<string>>>();
	const budgetExhausted = new Error("Fetch budget exhausted");
	const transport = options?.httpClient ?? fetch;
	const fetchOptions: FederationOptions = {
		...options,
		httpClient: async (input, init) => {
			if (options?.signal?.aborted || init?.signal?.aborted)
				throw new DOMException("Operation aborted", "AbortError");
			if (fetchBudget.remaining <= 0) {
				incomplete = true;
				throw budgetExhausted;
			}
			fetchBudget.remaining--;
			return transport(input, init);
		},
	};
	function retrieve(
		store: Map<string, Promise<Result<string>>>,
		key: string,
		load: () => Promise<Result<string>>,
	): Promise<Result<string>> {
		let pending = store.get(key);
		if (!pending) {
			pending = limiter(load).then(
				(result) => {
					if (!result.ok && result.error.cause === budgetExhausted && !options?.signal?.aborted)
						return err(
							federationError(InternalErrorCode.TrustChainInvalid, "Fetch budget exhausted"),
						);
					return result;
				},
				(cause: unknown) => {
					if (options?.signal?.aborted) incomplete = true;
					return err(
						federationError(
							options?.signal?.aborted ? InternalErrorCode.Timeout : InternalErrorCode.Network,
							cause instanceof Error ? cause.message : "Statement retrieval failed",
							cause,
						),
					);
				},
			);
			store.set(key, pending);
		}
		return pending;
	}
	const configuration = async (id: string): Promise<Result<Configuration>> => {
		let pending = authenticatedConfigurations.get(id);
		if (!pending) {
			pending = (async (): Promise<Result<Configuration>> => {
				const fetched = await retrieve(configurations, id, () =>
					fetchEntityConfiguration(id as EntityId, fetchOptions),
				);
				if (!fetched.ok) return fetched;
				const registration =
					id === entityId &&
					options?.entityConfigurationJwt !== undefined &&
					options.explicitRegistrationAudience !== undefined
						? { audience: options.explicitRegistrationAudience }
						: undefined;
				const checked = await validateEntityConfigurationPublication(
					fetched.value,
					options,
					registration,
				);
				if (!checked.valid)
					return err(
						federationError(
							checked.errors[0]?.code ?? InternalErrorCode.TrustChainInvalid,
							`Invalid EC '${id}': ${checked.errors.map((error) => error.message).join("; ")}`,
						),
					);
				if (checked.statement.payload.iss !== id || checked.statement.payload.sub !== id)
					return err(
						federationError(
							InternalErrorCode.TrustChainInvalid,
							`EC identity mismatch: expected '${id}'`,
						),
					);
				return ok({ jwt: fetched.value, statement: checked.statement });
			})();
			authenticatedConfigurations.set(id, pending);
		}
		const result = await pending;
		if (options?.signal?.aborted) {
			incomplete = true;
			return err(federationError(InternalErrorCode.Timeout, "Resolution aborted"));
		}
		if (result.ok) {
			// Shared authentication does not extend an EC's lifetime during traversal.
			const time = validateEntityStatementTimeClaims(result.value.statement.payload, options);
			if (!time.ok) return time;
			configurationJwts.set(id, result.value.jwt);
		}
		return result;
	};
	const statement = (issuer: string, subject: string, endpoint: string) =>
		retrieve(statements, JSON.stringify([issuer, subject]), () =>
			fetchSubordinateStatement(endpoint, subject as EntityId, {
				...fetchOptions,
				issuer: issuer as EntityId,
			}),
		);

	if (options?.entityConfigurationJwt !== undefined)
		configurations.set(entityId, Promise.resolve(ok(options.entityConfigurationJwt)));
	const leafEcResult = await configuration(entityId);
	if (!leafEcResult.ok) {
		return {
			chains: [],
			errors: [leafEcResult.error],
			...(incomplete || options?.signal?.aborted ? { incomplete: true as const } : {}),
		};
	}
	const { jwt: leafEcJwt, statement: leafStatement } = leafEcResult.value;
	const leafPayload = leafStatement.payload;

	const hints = (leafPayload as Record<string, unknown>).authority_hints as string[] | undefined;

	if (trustAnchors.has(entityId)) {
		// Federation §4.1 allows anchors with superiors. Include the direct
		// candidate and keep exploring hints for paths to other configured anchors.
		chains.push({
			statements: [leafEcJwt],
			entityConfigurations: new Map(configurationJwts),
			entityId,
			trustAnchorId: entityId,
			expiresAt: calculateChainExpiration([leafStatement]),
		});
		if (!hints || hints.length === 0) return { chains, errors };
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
			incomplete = true;
			errors.push(
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`Max chain depth (${maxDepth}) exceeded`,
				),
			);
			return;
		}

		if (options?.signal?.aborted) {
			incomplete = true;
			return;
		}

		let filteredHints = [...new Set(currentHints.slice(0, maxHints))];
		if (currentHints.length > maxHints) {
			incomplete = true;
			errors.push(
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`Max authority hints (${maxHints}) exceeded`,
				),
			);
		}
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
			filteredHints.map(async (hint) => {
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

				// Cached statements can participate in many paths. Bound that work
				// separately from the number of HTTP requests (Federation §18.1).
				if (remainingSteps <= 0) {
					incomplete = true;
					if (!stepLimitReported) {
						stepLimitReported = true;
						errors.push(
							federationError(
								InternalErrorCode.TrustChainInvalid,
								`Max resolution steps (${maxSteps}) exceeded`,
							),
						);
					}
					return;
				}
				remainingSteps--;
				const hintEcResult = await configuration(hint);
				if (!hintEcResult.ok) {
					errors.push(hintEcResult.error);
					return;
				}

				const hintPayload = hintEcResult.value.statement.payload;
				const hintHints = hintPayload.authority_hints;
				if (!trustAnchors.has(hint as EntityId) && (!hintHints || hintHints.length === 0)) {
					errors.push(
						federationError(
							InternalErrorCode.TrustChainInvalid,
							`Entity '${hint}' has no authority_hints and is not a trust anchor`,
						),
					);
					return;
				}
				const hintMeta = hintPayload.metadata as
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

				const ssResult = await statement(hint, currentEntityId, fetchEndpoint);
				if (!ssResult.ok) {
					errors.push(ssResult.error);
					return;
				}

				if (trustAnchors.has(hint as EntityId)) {
					const fullChain = [...chainSoFar, ssResult.value, hintEcResult.value.jwt];
					const parsed = fullChain.map((jwt) => {
						const d = decodeEntityStatement(jwt);
						return d.ok ? d.value : null;
					});
					if (parsed.every((p) => p !== null)) {
						chains.push({
							statements: fullChain,
							entityConfigurations: new Map(configurationJwts),
							entityId,
							trustAnchorId: hint as EntityId,
							expiresAt: calculateChainExpiration(parsed as NonNullable<(typeof parsed)[0]>[]),
						});
					}
					return;
				}

				await buildChains(
					hint,
					hintHints ?? [],
					[...chainSoFar, ssResult.value],
					branchVisited,
					depth + 1,
				);
			}),
		);

		for (const result of settled) {
			if (result.status === "rejected") {
				if (options?.signal?.aborted) incomplete = true;
				errors.push(
					federationError(
						options?.signal?.aborted ? InternalErrorCode.Timeout : InternalErrorCode.Network,
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

	if (options?.signal?.aborted) incomplete = true;
	if (chains.length > 0) safeLogger(options?.logger)?.info("Trust chains resolved");
	else safeLogger(options?.logger)?.warn("No trust chain could be resolved");
	return { chains, errors, ...(incomplete ? { incomplete: true as const } : {}) };
}
