/** Compact JWT signing through a captured host keyring entry. */
import {
	CryptoError,
	DEFAULT_JWS_REGISTRY,
	type FederationArtifact,
	type JwsAlgorithm,
	type JwsAlgorithmRegistry,
	type KeyringEntry,
	signCompactJws,
} from "@oidfed/crypto";
import { JwtTyp } from "../constants.js";
import { federationAlgorithms } from "../crypto-context.js";
import type { FederationOptions } from "../types.js";
export interface SignEntityStatementOptions {
	readonly alg?: JwsAlgorithm;
	readonly typ?: string;
	readonly extraHeaders?: Record<string, unknown>;
	readonly maxBytes?: number | undefined;
	readonly algorithmRegistry?: JwsAlgorithmRegistry | undefined;
	readonly allowedFederationAlgorithms?: readonly string[] | undefined;
	readonly allowedAlgorithmsForArtifact?: FederationOptions["allowedAlgorithmsForArtifact"];
	/** The operation that owns this JWT profile. Required when an artifact policy is configured. */
	readonly artifact?: FederationArtifact | undefined;
}
/** Sign a payload without resolving another key. Publication must use this entry's keys. */
export async function signEntityStatement(
	payload: Record<string, unknown>,
	entry: KeyringEntry,
	options?: SignEntityStatementOptions,
): Promise<string> {
	for (const name of ["alg", "kid", "typ"])
		if (options?.extraHeaders && Object.hasOwn(options.extraHeaders, name))
			throw new TypeError(`extraHeaders must not override '${name}'`);
	const registry = options?.algorithmRegistry ?? DEFAULT_JWS_REGISTRY;
	if (options?.alg !== undefined && !registry.algorithm(options.alg))
		throw new TypeError(`Unsupported signing algorithm: ${options.alg}`);
	const { alg, kid } = entry.signer.publicJwk;
	if (!federationAlgorithms(options, options?.artifact).includes(alg))
		throw new CryptoError(
			"UNSUPPORTED_ALGORITHM",
			"Signing algorithm is outside the configured policy",
		);
	if (options?.alg !== undefined && options.alg !== alg)
		throw new TypeError("Signing algorithm mismatch");
	return signCompactJws(
		payload,
		{ ...options?.extraHeaders, alg, kid, typ: options?.typ ?? JwtTyp.EntityStatement },
		entry.signer,
		{ maxBytes: options?.maxBytes, algorithmRegistry: options?.algorithmRegistry },
	);
}
