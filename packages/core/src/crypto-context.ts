/** Bind application dependencies while combining narrower operation policies. */
import {
	CLASSICAL_ALGORITHMS,
	DEFAULT_JWS_REGISTRY,
	type JwsAlgorithmRegistry,
} from "@oidfed/crypto";
import type { BoundFederationOptions, CryptoContext, FederationOptions } from "./types.js";

/** Validate the host boundary without exporting private keys or exercising signing custody. */
export function validateCryptoContext(crypto: CryptoContext): void {
	if (!crypto?.engine || !crypto.keyring || typeof crypto.keyring.entry !== "function")
		throw new TypeError("Host crypto requires an engine and keyring");
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

/**
 * Apply host, role and call settings in order, keeping the engine bound to the host.
 * Algorithm lists intersect and resource ceilings take the smallest configured value.
 */
export function bindFederationOptions(
	crypto: Pick<CryptoContext, "engine" | "algorithmRegistry">,
	...policies: readonly (BoundFederationOptions | undefined)[]
): FederationOptions {
	const combined: BoundFederationOptions = {};
	for (const policy of policies) Object.assign(combined, policy);
	const result: FederationOptions = {
		...combined,
		engine: crypto.engine,
		algorithmRegistry: registryFor(crypto),
	};
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
	for (const name of ["maxCompactBytes", "maxVerificationCandidates"] as const) {
		const values = policies.flatMap((policy) =>
			policy?.[name] === undefined ? [] : [policy[name]],
		);
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

/** Adapt Federation Entity Key policy for generic JWS operations. */
export function federationJwsOptions<
	T extends { readonly allowedFederationAlgorithms?: readonly string[] | undefined },
>(options: T): T & { readonly allowedAlgorithms: readonly string[] } {
	return {
		...options,
		allowedAlgorithms: options.allowedFederationAlgorithms ?? CLASSICAL_ALGORITHMS,
	};
}

/** Select the same policy and registry for outbound federation signatures. */
export function federationSigningOptions(
	options: Pick<
		FederationOptions,
		"allowedFederationAlgorithms" | "algorithmRegistry" | "maxCompactBytes"
	>,
) {
	return {
		allowedFederationAlgorithms: options.allowedFederationAlgorithms ?? CLASSICAL_ALGORITHMS,
		algorithmRegistry: registryFor(options),
		maxBytes: options.maxCompactBytes,
	};
}
