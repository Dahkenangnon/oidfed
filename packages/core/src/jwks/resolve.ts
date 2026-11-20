/**
 * Resolve protocol keys from entity-type metadata and report the selected source.
 *
 * Try sources in this order:
 * 1. `signed_jwks_uri`: signed with a trusted Federation Entity Key.
 * 2. `jwks`: inline keys covered by the trust chain.
 * 3. `jwks_uri`: keys retrieved over HTTPS.
 *
 * Return the first error by default. With `allowFallback: true`, continue after
 * availability failures. Invalid signatures, identities, payloads, or response
 * formats stop resolution.
 */

// biome-ignore assist/source/organizeImports: Preserve dependency evaluation order.
import { safeLogger } from "../logging.js";
import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import type { VerifySignedJwkSetOptions } from "./signed-jwk-set.js";
import { validateExpectedIssuer } from "../federation-api/verify-issuer.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import { type JWK, type JWKSet, MetadataJWKSetSchema } from "../schemas/jwk.js";
import { isAvailabilityFailure } from "../http/fetch-failure.js";
import type { Clock, FederationOptions } from "../types.js";
import { fetchJwkSet } from "./jwks-uri.js";
import { fetchSignedJwkSet } from "./signed-jwks-uri.js";
import { validateJwkSetUseRequirement } from "./use-requirement.js";

export type EntityKeysSource = "jwks" | "jwks_uri" | "signed_jwks_uri";

export interface ResolveEntityKeysOptions extends FederationOptions, VerifySignedJwkSetOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
	/** Try the next source after transport/timeouts, HTTP 404/410 or transient 5xx; never after integrity failures. Default: false. */
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
	options: ResolveEntityKeysOptions,
): Promise<Result<ResolvedEntityKeys, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting resolve entity keys");

	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (!EntityIdSchema.safeParse(options?.expectedOwner).success)
		return err(
			federationError(FederationErrorCode.InvalidMetadata, "A valid expectedOwner is required"),
		);
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
			options,
		});
		if (attempt.ok) {
			safeLogger(options.logger)?.info("Entity protocol keys resolved");
			return ok({ keys: attempt.value, source });
		}
		errors.push({ source, error: attempt.error });
		if (
			!options?.allowFallback ||
			options.signal?.aborted ||
			!isAvailabilityFailure(attempt.error)
		) {
			safeLogger(options.logger)?.warn("Entity protocol key resolution failed");
			return err(attempt.error);
		}
		if (source !== present.at(-1))
			safeLogger(options.logger)?.info(
				"Trying another key representation after an availability failure",
			);
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
		options: ResolveEntityKeysOptions;
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
			const useResult = validateJwkSetUseRequirement(
				result.value.keys,
				ctx.options.algorithmRegistry,
			);
			if (!useResult.ok) return useResult;
			return ok([...result.value.keys]);
		}
		case "jwks": {
			const parsed = MetadataJWKSetSchema.safeParse(ctx.inlineJwks);
			if (!parsed.success) {
				return err(
					federationError(
						FederationErrorCode.InvalidMetadata,
						`Inline 'jwks' is not a valid JWK Set: ${parsed.error.message}`,
					),
				);
			}
			const useResult = validateJwkSetUseRequirement(
				parsed.data.keys,
				ctx.options.algorithmRegistry,
			);
			if (!useResult.ok) return useResult;
			return ok(parsed.data.keys);
		}
		case "jwks_uri": {
			const result = await fetchJwkSet(ctx.plainUri as string, ctx.options);
			if (!result.ok) return result;
			return ok([...result.value.keys]);
		}
	}
}
