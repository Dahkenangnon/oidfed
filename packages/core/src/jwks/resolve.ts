/**
 * Unified entity-key resolver. Picks among the three JWK Set representations
 * (`signed_jwks_uri`, `jwks`, `jwks_uri`) defined in entity-type metadata
 * and returns the resolved key set tagged with its source.
 *
 * Priority order (federation-preferred → least preferred):
 *   1. `signed_jwks_uri` — cryptographic integrity tied to a Federation Entity Key.
 *   2. `jwks` — inline keys, already in the trust chain.
 *   3. `jwks_uri` — plain HTTPS fetch, no per-key signing.
 *
 * Strict mode (default) returns the first error encountered. With
 * `allowFallback: true`, a failure on a higher-priority representation
 * cascades to the next-priority representation that is present, and only
 * after all present branches fail does the resolver return an aggregated
 * error.
 */
import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { type JWK, type JWKSet, JWKSetSchema } from "../schemas/jwk.js";
import type { Clock, FederationOptions } from "../types.js";
import { fetchJwkSet } from "./jwks-uri.js";
import { fetchSignedJwkSet } from "./signed-jwks-uri.js";
import { validateJwkSetUseRequirement } from "./use-requirement.js";

export type EntityKeysSource = "jwks" | "jwks_uri" | "signed_jwks_uri";

export interface ResolveEntityKeysOptions extends FederationOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
	/** When true, falls through to the next-priority representation on failure. Default: false. */
	allowFallback?: boolean;
}

export interface ResolvedEntityKeys {
	keys: JWK[];
	source: EntityKeysSource;
}

/** Resolve an entity's public keys from its entity-type metadata. */
export async function resolveEntityKeys(
	entityMetadata: Record<string, unknown>,
	federationEntityKeys: JWKSet,
	options?: ResolveEntityKeysOptions,
): Promise<Result<ResolvedEntityKeys, FederationError>> {
	const signedUri =
		typeof entityMetadata.signed_jwks_uri === "string" ? entityMetadata.signed_jwks_uri : undefined;
	const inlineJwks = entityMetadata.jwks;
	const plainUri =
		typeof entityMetadata.jwks_uri === "string" ? entityMetadata.jwks_uri : undefined;

	const present: EntityKeysSource[] = [];
	if (signedUri) present.push("signed_jwks_uri");
	if (inlineJwks) present.push("jwks");
	if (plainUri) present.push("jwks_uri");

	if (present.length === 0) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Entity metadata contains no JWK Set representation (signed_jwks_uri, jwks, or jwks_uri)",
			),
		);
	}

	const errors: { source: EntityKeysSource; error: FederationError }[] = [];

	for (const source of present) {
		const attempt = await tryResolveSource(source, {
			signedUri,
			inlineJwks,
			plainUri,
			federationEntityKeys,
			...(options !== undefined ? { options } : {}),
		});
		if (attempt.ok) {
			return ok({ keys: attempt.value, source });
		}
		errors.push({ source, error: attempt.error });
		if (!options?.allowFallback) {
			return err(attempt.error);
		}
	}

	const summary = errors.map((e) => `[${e.source}] ${e.error.description}`).join("; ");
	return err(
		federationError(
			FederationErrorCode.InvalidMetadata,
			`All JWK Set representations failed to resolve: ${summary}`,
		),
	);
}

async function tryResolveSource(
	source: EntityKeysSource,
	ctx: {
		signedUri: string | undefined;
		inlineJwks: unknown;
		plainUri: string | undefined;
		federationEntityKeys: JWKSet;
		options?: ResolveEntityKeysOptions;
	},
): Promise<Result<JWK[], FederationError>> {
	switch (source) {
		case "signed_jwks_uri": {
			const fetchOpts = ctx.options;
			const result = await fetchSignedJwkSet(
				ctx.signedUri as string,
				ctx.federationEntityKeys,
				fetchOpts,
			);
			if (!result.ok) return result;
			const useResult = validateJwkSetUseRequirement(result.value.keys);
			if (!useResult.ok) return useResult;
			return ok(result.value.keys);
		}
		case "jwks": {
			const parsed = JWKSetSchema.safeParse(ctx.inlineJwks);
			if (!parsed.success) {
				return err(
					federationError(
						FederationErrorCode.InvalidMetadata,
						`Inline 'jwks' is not a valid JWK Set: ${parsed.error.message}`,
					),
				);
			}
			const useResult = validateJwkSetUseRequirement(parsed.data.keys);
			if (!useResult.ok) return useResult;
			return ok(parsed.data.keys);
		}
		case "jwks_uri": {
			const result = await fetchJwkSet(ctx.plainUri as string, ctx.options);
			if (!result.ok) return result;
			return ok(result.value.keys);
		}
	}
}
