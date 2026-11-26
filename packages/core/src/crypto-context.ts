/** Bind application dependencies while combining narrower operation policies. */
import {
	CLASSICAL_ALGORITHMS,
	CryptoError,
	DEFAULT_JWS_REGISTRY,
	FEDERATION_ARTIFACTS,
	type FederationArtifact,
	type JwsAlgorithmRegistry,
} from "@oidfed/crypto";
import { callSynchronous } from "./callbacks.js";
import type { FederationStorage } from "./storage/contracts.js";
import type { BoundFederationOptions, CryptoContext, FederationOptions } from "./types.js";

/** Capture host crypto configuration while retaining the adapters and their signing custody. */
export function snapshotCryptoContext(crypto: CryptoContext): Readonly<CryptoContext> {
	const {
		engine,
		keyring,
		algorithmRegistry,
		federationPurpose,
		readPublishedFederationJwks,
		history,
	} = crypto;
	return Object.freeze({
		engine,
		keyring,
		...(algorithmRegistry ? { algorithmRegistry } : {}),
		...(federationPurpose !== undefined ? { federationPurpose } : {}),
		...(readPublishedFederationJwks !== undefined ? { readPublishedFederationJwks } : {}),
		...(history !== undefined ? { history } : {}),
	});
}

/** Validate the host boundary without exporting private keys or exercising signing custody. */
export function validateCryptoContext(crypto: CryptoContext): void {
	if (!crypto?.engine || !crypto.keyring || typeof crypto.keyring.entry !== "function")
		throw new TypeError("Host crypto requires an engine and keyring");
	if (
		crypto.readPublishedFederationJwks !== undefined &&
		typeof crypto.readPublishedFederationJwks !== "function"
	)
		throw new TypeError("Published Federation JWKS reader must be a function");
	if (crypto.history !== undefined && typeof crypto.history?.getHistoricalKeys !== "function")
		throw new TypeError("Crypto history requires getHistoricalKeys");
	for (const name of ["verify", "validatePublicKey", "digest", "random"] as const)
		if (typeof crypto.engine[name] !== "function")
			throw new TypeError(`CryptoEngine requires ${name}`);
	if (
		!Array.isArray(crypto.engine.algorithms) ||
		!crypto.engine.algorithms.every(
			(id) => typeof id === "string" && registryFor(crypto).algorithm(id),
		) ||
		new Set(crypto.engine.algorithms).size !== crypto.engine.algorithms.length
	)
		throw new TypeError("CryptoEngine requires distinct supported algorithms");
}

/** Validate the optional Resolve budget before composing multiple host limits. */
export function assertResolveResponderEvidenceBudget(value: number | undefined): void {
	// Larger delays overflow the timer range instead of giving the operation more time.
	if (value !== undefined && (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647))
		throw new TypeError("resolveResponderEvidenceBudgetMs must be an integer from 1 to 2147483647");
}

/**
 * Apply host, role and call settings in order, keeping the engine and storage bound to the host.
 * Algorithm lists intersect and resource ceilings take the smallest configured value.
 */
export function bindFederationOptions(
	dependencies:
		| Pick<CryptoContext, "engine" | "algorithmRegistry">
		| {
				readonly crypto: Pick<CryptoContext, "engine" | "algorithmRegistry">;
				readonly storage?: FederationStorage | undefined;
		  },
	...policies: readonly (BoundFederationOptions | undefined)[]
): FederationOptions {
	const crypto = "crypto" in dependencies ? dependencies.crypto : dependencies;
	const storage = "crypto" in dependencies ? dependencies.storage : undefined;
	const combined: BoundFederationOptions = {};
	for (const policy of policies) Object.assign(combined, policy);
	const result: FederationOptions = {
		...combined,
		engine: crypto.engine,
		algorithmRegistry: registryFor(crypto),
	};
	const endpointPolicies = policies.flatMap((policy) =>
		policy?.authorizeEndpointRequest === undefined ? [] : [policy.authorizeEndpointRequest],
	);
	if (endpointPolicies[0]) result.authorizeEndpointRequest = endpointPolicies[0];
	if (endpointPolicies.length > 1)
		result.authorizeEndpointRequest = async (input) => {
			for (const policy of endpointPolicies) {
				if (input.signal.aborted) throw new DOMException("Operation cancelled", "AbortError");
				const decision = await policy(input);
				// Let the handler distinguish a denial from an invalid result at runtime.
				if (decision !== true) return decision;
			}
			return true;
		};
	Object.defineProperty(result, "storage", { value: storage, enumerable: true });
	const lists = policies.flatMap((policy) =>
		policy?.allowedAlgorithms === undefined ? [] : [policy.allowedAlgorithms],
	);
	if (lists.length)
		Object.defineProperty(result, "allowedAlgorithms", {
			value: lists
				.slice(1)
				.reduce(
					(allowed, list) => allowed.filter((value) => list.includes(value)),
					[...(lists[0] ?? [])],
				),
			enumerable: true,
		});
	const federationLists = policies.map((policy) => policy?.allowedFederationAlgorithms);
	const [ceiling, ...narrowing] = federationLists;
	for (const list of federationLists) {
		if (
			list !== undefined &&
			(!Array.isArray(list) ||
				!Array.from(list).every(
					(id) => typeof id === "string" && registryFor(crypto).algorithm(id),
				))
		)
			throw new TypeError("Federation algorithm policy requires registered identifiers");
	}
	Object.defineProperty(result, "allowedFederationAlgorithms", {
		value: Object.freeze(
			(ceiling ?? CLASSICAL_ALGORITHMS).filter((id) =>
				narrowing.every((list) => list === undefined || list.includes(id)),
			),
		),
		enumerable: true,
	});
	const artifactPolicies = policies.flatMap((policy) =>
		policy?.allowedAlgorithmsForArtifact === undefined ? [] : [policy.allowedAlgorithmsForArtifact],
	);
	if (artifactPolicies.some((policy) => typeof policy !== "function"))
		throw new TypeError("Federation artifact algorithm policy requires a function");
	if (artifactPolicies.length)
		Object.defineProperty(result, "allowedAlgorithmsForArtifact", {
			value: (artifact: FederationArtifact) => {
				const lists = artifactPolicies.map((policy) =>
					readArtifactAlgorithms(policy, artifact, registryFor(crypto)),
				);
				return lists
					.slice(1)
					.reduce(
						(allowed, list) => allowed.filter((algorithm) => list.includes(algorithm)),
						lists[0] ?? [],
					);
			},
			enumerable: true,
		});
	for (const name of [
		"maxCompactBytes",
		"maxVerificationCandidates",
		"resolveResponderEvidenceBudgetMs",
	] as const) {
		const values = policies.flatMap((policy) =>
			policy?.[name] === undefined ? [] : [policy[name]],
		);
		if (name === "resolveResponderEvidenceBudgetMs")
			values.forEach(assertResolveResponderEvidenceBudget);
		if (values.length)
			Object.defineProperty(result, name, {
				value: Math.min(...values),
				enumerable: true,
				writable: false,
			});
	}
	return result;
}

/** Resolve application definitions, or use the built-in registry for standalone operations. */
export function registryFor(options?: {
	readonly algorithmRegistry?: JwsAlgorithmRegistry | undefined;
}): JwsAlgorithmRegistry {
	return options?.algorithmRegistry ?? DEFAULT_JWS_REGISTRY;
}

type ArtifactAlgorithmPolicy = NonNullable<FederationOptions["allowedAlgorithmsForArtifact"]>;
type FederationAlgorithmOptions = Pick<
	FederationOptions,
	"algorithmRegistry" | "allowedFederationAlgorithms" | "allowedAlgorithmsForArtifact"
>;

/** Validate a host callback before trusting any algorithm identifiers it returns. */
function readArtifactAlgorithms(
	policy: ArtifactAlgorithmPolicy,
	artifact: FederationArtifact,
	registry: JwsAlgorithmRegistry,
): readonly string[] {
	const allowed = callSynchronous(
		() => {
			const declared: unknown = policy(artifact);
			return Array.isArray(declared) ? Array.from(declared as readonly unknown[]) : declared;
		},
		(value): value is readonly string[] =>
			Array.isArray(value) &&
			value.every(
				(algorithm: unknown) =>
					typeof algorithm === "string" && registry.algorithm(algorithm) !== undefined,
			),
	);
	if (!allowed.ok)
		throw new CryptoError(
			"CRYPTO_OPERATION_FAILED",
			"Invalid Federation artifact algorithm policy",
		);
	return allowed.value;
}

/** Narrow the existing Federation allowlist for an artifact selected by the operation. */
export function federationAlgorithms(
	options?: FederationAlgorithmOptions,
	artifact?: FederationArtifact,
): readonly string[] {
	const allowed = options?.allowedFederationAlgorithms ?? CLASSICAL_ALGORITHMS;
	if (options?.allowedAlgorithmsForArtifact === undefined) return allowed;
	// The JWT typ is shared by some artifacts. Its caller supplies the expected operation.
	if (artifact === undefined || !FEDERATION_ARTIFACTS.includes(artifact))
		throw new CryptoError(
			"CRYPTO_OPERATION_FAILED",
			"Federation artifact algorithm policy requires an artifact",
		);
	const restricted = readArtifactAlgorithms(
		options.allowedAlgorithmsForArtifact,
		artifact,
		registryFor(options),
	);
	return allowed.filter((algorithm) => restricted.includes(algorithm));
}

/** Adapt Federation Entity Key policy for generic JWS operations. */
export function federationJwsOptions<T extends FederationAlgorithmOptions>(
	options: T,
	artifact?: FederationArtifact,
): T & { readonly allowedAlgorithms: readonly string[] } {
	return { ...options, allowedAlgorithms: federationAlgorithms(options, artifact) };
}

/** Select the same policy and registry for outbound federation signatures. */
export function federationSigningOptions(
	options: FederationAlgorithmOptions & Pick<FederationOptions, "maxCompactBytes">,
	artifact?: FederationArtifact,
) {
	return {
		allowedFederationAlgorithms: options.allowedFederationAlgorithms ?? CLASSICAL_ALGORITHMS,
		allowedAlgorithmsForArtifact: options.allowedAlgorithmsForArtifact,
		artifact,
		algorithmRegistry: registryFor(options),
		maxBytes: options.maxCompactBytes,
	};
}
