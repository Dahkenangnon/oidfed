/**
 * Fetch a public JWK Set from `jwks_uri`, validate it with `MetadataJWKSetSchema`,
 * and check the conditional `use` requirement.
 */

import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { performFetch } from "../http/fetch.js";
import { safeLogger } from "../logging.js";
import { parseMetadataUrl } from "../metadata-url.js";
import { type JWKSet, MetadataJWKSetSchema } from "../schemas/jwk.js";
import type { FederationOptions } from "../types.js";
import { validateJwkSetUseRequirement } from "./use-requirement.js";

/**
 * Fetch and parse a plain JWK Set from `jwks_uri`.
 *
 * - URL MUST use https and MUST NOT contain a fragment.
 * - HTTP GET; non-2xx is rejected by the underlying fetcher.
 * - Body MUST parse as JSON and conform to `MetadataJWKSetSchema`.
 * - The conditional `use` rule is enforced (mixed signing/encryption keys
 *   require `use` on every key).
 */
export async function fetchJwkSet(
	url: string,
	options: FederationOptions,
): Promise<Result<JWKSet, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch jwk set");

	const parsed = parseMetadataUrl(url, FederationErrorCode.InvalidMetadata);
	if (!parsed.ok) return parsed;

	// RFC 7517 doesn't pin a media type for jwks_uri; servers commonly serve
	// application/json or application/jwk-set+json. We send application/json in
	// the Accept header but tolerate any successful 2xx response (Content-Type
	// validation is skipped via `expectedContentType: null`).
	const fetched = await performFetch(url, {
		...options,
		accept: "application/json",
		expectedContentType: null,
	});
	if (!fetched.ok) return fetched;

	let raw: unknown;
	try {
		raw = JSON.parse(fetched.value);
	} catch {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`jwks_uri response is not valid JSON: ${url}`,
			),
		);
	}

	const validated = MetadataJWKSetSchema.safeParse(raw);
	if (!validated.success) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`jwks_uri response is not a valid JWK Set: ${validated.error.message}`,
			),
		);
	}

	const useResult = validateJwkSetUseRequirement(validated.data.keys, options.algorithmRegistry);
	if (!useResult.ok) return useResult;

	return ok(validated.data);
}
