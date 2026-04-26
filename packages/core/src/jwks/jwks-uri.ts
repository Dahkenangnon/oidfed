/**
 * HTTP fetcher for `jwks_uri` — performs the HTTPS GET, validates the JSON
 * shape against `JWKSetSchema`, and applies the conditional `use` rule.
 */
import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { type JWKSet, JWKSetSchema } from "../schemas/jwk.js";
import { performFetch } from "../trust-chain/fetch.js";
import type { FederationOptions } from "../types.js";
import { validateJwkSetUseRequirement } from "./use-requirement.js";

/**
 * Fetch and parse a plain JWK Set from `jwks_uri`.
 *
 * - URL MUST use https and MUST NOT contain a fragment.
 * - HTTP GET; non-2xx is rejected by the underlying fetcher.
 * - Body MUST parse as JSON and conform to `JWKSetSchema`.
 * - The conditional `use` rule is enforced (mixed signing/encryption keys
 *   require `use` on every key).
 */
export async function fetchJwkSet(
	url: string,
	options?: FederationOptions,
): Promise<Result<JWKSet, FederationError>> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return err(federationError(FederationErrorCode.InvalidMetadata, `Invalid URL: ${url}`));
	}
	if (parsed.protocol !== "https:") {
		return err(
			federationError(FederationErrorCode.InvalidMetadata, `URL must use https scheme: ${url}`),
		);
	}
	if (parsed.hash) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`URL must not contain a fragment: ${url}`,
			),
		);
	}

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

	const validated = JWKSetSchema.safeParse(raw);
	if (!validated.success) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`jwks_uri response is not a valid JWK Set: ${validated.error.message}`,
			),
		);
	}

	const useResult = validateJwkSetUseRequirement(validated.data.keys);
	if (!useResult.ok) return useResult;

	return ok(validated.data);
}
